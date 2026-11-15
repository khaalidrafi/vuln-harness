#!/usr/bin/env python3
"""orchestrator.py — model-agnostic vulnerability harness (CF-blog style).

Pipeline per repo, stages persisted in SQLite keyed (run_id, repo, stage):

  recon     1 agent  -> architecture.md + threat model (built-in attack
                       classes + repo-specific classes it invents)
  hunt      N agents -> one task per attack class (discovery model)
  validate  N agents -> adversarial: try to DISPROVE each finding
                       (validation model — a DIFFERENT model per the blog)
  mechanical           schema check + line numbers must exist in source
  report               human-readable MD + findings.json

Design rules taken from the blog:
  * models are interchangeable parts: discovery != validation model
  * persistence before parallelism: every stage writes to SQLite, any
    stage can resume/retry without redoing work
  * the LLM is a stateless compute engine — state lives in the DB
  * in-band API errors returned inside a 200 response are classified as
    failures, not successes
  * the validator may not file new findings; it only confirms/refutes

Usage:
  orchestrator.py run   --repo /path/to/checkout [--db harness.db]
  orchestrator.py resume --run-id <id>
  orchestrator.py report --run-id <id> [--out report.md]

Env: HARNESS_DISCOVERY_MODEL (required), HARNESS_VALIDATION_MODEL
     (required, DIFFERENT model), and per-lane credentials — models may
     not exist on one API:
       HARNESS_DISCOVERY_API_KEY / HARNESS_DISCOVERY_BASE_URL
       HARNESS_VALIDATION_API_KEY / HARNESS_VALIDATION_BASE_URL
     Both fall back to shared HARNESS_API_KEY / HARNESS_BASE_URL
     (default base https://api.openai.com/v1).
"""
import argparse
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PROMPTS = os.path.join(HERE, "..", "prompts")
BUILTIN_CLASSES = [
    "hardcoded-secrets", "command-injection", "sql-injection",
    "path-traversal", "ssrf", "unsafe-deserialization",
    "auth-bypass", "insecure-http-transport", "dependency-confusion",
    "log-injection", "timing-side-channel",
]

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(
  run_id TEXT PRIMARY KEY, repo TEXT, path TEXT, started REAL, status TEXT);
CREATE TABLE IF NOT EXISTS tasks(
  run_id TEXT, repo TEXT, stage TEXT, cls TEXT, model TEXT,
  status TEXT, output TEXT, updated REAL,
  PRIMARY KEY (run_id, repo, stage, cls));
"""


def db(dbfile):
    c = sqlite3.connect(dbfile)
    c.executescript(SCHEMA)
    return c


def env(name, default=None):
    return os.environ.get(name, default)


def classify_response(text):
    """Blog trap: transient API errors can arrive as 200-OK body text."""
    low = text[:400].lower()
    if any(k in low for k in ("rate limit", "overloaded", "quota exceeded",
                              "timeout", "bad gateway", "service unavailable",
                              "invalid api key", "unauthorized")):
        return "TRANSIENT_ERROR"
    return "OK"


def lane_creds(lane):
    """Per-lane credentials — models may not exist on one API.

    lane is 'discovery' or 'validation'. Resolution order:
      HARNESS_<LANE>_API_KEY   -> HARNESS_API_KEY   (fallback)
      HARNESS_<LANE>_BASE_URL  -> HARNESS_BASE_URL  (fallback)
    One provider serves both lanes when only HARNESS_API_KEY is set;
    two providers split cleanly when the per-lane vars are set too.
    """
    key = env(f"HARNESS_{lane.upper()}_API_KEY") or env("HARNESS_API_KEY")
    base = (env(f"HARNESS_{lane.upper()}_BASE_URL")
            or env("HARNESS_BASE_URL", "https://api.openai.com/v1"))
    return key, base.rstrip("/")


def llm(model, lane, system, user, max_retries=3):
    """Minimal OpenAI-compatible chat call. Returns (text, status)."""
    key, base = lane_creds(lane)
    if not key or not model:
        return "", "NO_MODEL_CONFIGURED"
    body = json.dumps({"model": model,
                       "messages": [{"role": "system", "content": system},
                                    {"role": "user", "content": user}],
                       "temperature": 0.2}).encode()
    req = urllib.request.Request(
        base + "/chat/completions", data=body,
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + key})
    for attempt in range(max_retries):
        try:
            with urllib.request.urlopen(req, timeout=600) as r:
                data = json.load(r)
            text = data["choices"][0]["message"]["content"]
            if classify_response(text) == "TRANSIENT_ERROR":
                time.sleep(2 ** attempt * 5)
                continue
            return text, "OK"
        except (urllib.error.URLError, urllib.error.HTTPError,
                KeyError, json.JSONDecodeError) as e:
            if attempt == max_retries - 1:
                return f"error: {e}", "API_ERROR"
            time.sleep(2 ** attempt * 5)
    return "", "TRANSIENT_ERROR"


def prompt_file(name):
    with open(os.path.join(PROMPTS, name)) as f:
        return f.read()


def read_source(path, cap=120_000):
    """Repo context, truncated so each agent stays under ~25% context."""
    buf, budget = [], cap
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames[:] = [d for d in dirnames
                       if d not in (".git", "node_modules", "vendor")]
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            try:
                with open(p, encoding="utf-8", errors="ignore") as f:
                    t = f.read(cap)
            except OSError:
                continue
            buf.append(f"### {os.path.relpath(p, path)}\n{t}")
            budget -= len(t)
            if budget <= 0:
                return "\n\n".join(buf)
    return "\n\n".join(buf)


def start_run(c, repo, path):
    rid = f"r{int(time.time())}"
    c.execute("INSERT INTO runs VALUES (?,?,?,?,?)",
              (rid, repo, path, time.time(), "running"))
    c.commit()
    return rid


def run_stage(c, rid, repo, path, stage, cls, model, lane, system, user):
    row = c.execute("SELECT status FROM tasks WHERE run_id=? AND repo=? "
                    "AND stage=? AND cls=?", (rid, repo, stage, cls)).fetchone()
    if row and row[0] == "OK":
        return  # resumable: skip finished tasks
    text, status = llm(model, lane, system, user)
    c.execute("INSERT OR REPLACE INTO tasks VALUES (?,?,?,?,?,?,?,?)",
              (rid, repo, stage, cls, model or "", status, text, time.time()))
    c.commit()
    print(f"[{rid}] {repo} {stage}/{cls} -> {status}")


def extract_json(text):
    """Pull the first JSON object/array out of a model reply."""
    for i in range(len(text)):
        if text[i] in "[{":
            depth = 0
            for j in range(i, len(text)):
                if text[j] in "[{":
                    depth += 1
                elif text[j] in "]}":
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(text[i:j + 1])
                        except json.JSONDecodeError:
                            break
            break
    return None


def mechanical_check(findings, path):
    """Blog stage: validate findings.json mechanically — schema + lines."""
    ok, bad = [], []
    for f in findings or []:
        try:
            src = open(os.path.join(path, f["file"]),
                       encoding="utf-8", errors="ignore").readlines()
            n = int(f["line"])
            (ok if 1 <= n <= len(src) else bad).append(f)
        except Exception:
            bad.append(f)
    return ok, bad


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r1 = sub.add_parser("run"); r1.add_argument("--repo", required=True)
    r1.add_argument("--name"); r1.add_argument("--db", default="harness.db")
    r2 = sub.add_parser("resume"); r2.add_argument("--run-id", required=True)
    r2.add_argument("--db", default="harness.db")
    r3 = sub.add_parser("report"); r3.add_argument("--run-id", required=True)
    r3.add_argument("--db", default="harness.db")
    r3.add_argument("--out", default="report.md")
    a = ap.parse_args()
    c = db(a.db)

    if a.cmd == "run":
        path = os.path.abspath(a.repo)
        name = a.name or os.path.basename(path)
        rid = start_run(c, name, path)
    else:
        rid = a.run_id
        name, path = c.execute(
            "SELECT repo, path FROM runs WHERE run_id=?", (rid,)).fetchone()
        if not name:
            sys.exit(f"unknown run {rid}")

    disc = env("HARNESS_DISCOVERY_MODEL")
    vali = env("HARNESS_VALIDATION_MODEL")
    if not disc or not vali:
        sys.exit("set HARNESS_DISCOVERY_MODEL and HARNESS_VALIDATION_MODEL "
                 "(use two DIFFERENT models — that is the point)")

    # 1) RECON — writes the threat model itself, may invent extra classes
    src = read_source(path)
    run_stage(c, rid, name, path, "recon", "recon", disc, "discovery",
              prompt_file("recon.md"),
              f"Produce architecture.md + a threat model for this repo. "
              f"Built-in classes: {', '.join(BUILTIN_CLASSES)}. "
              f"Invent up to 3 repo-specific classes. "
              f"End with a JSON array of class names under a line "
              f"'CLASSES:'.\n\nSOURCE:\n{src[:60000]}")
    row = c.execute("SELECT output FROM tasks WHERE run_id=? AND repo=? "
                    "AND stage='recon' AND cls='recon'", (rid, name)).fetchone()
    classes = list(BUILTIN_CLASSES)
    if row:
        tail = row[0].split("CLASSES:")[-1]
        extra = extract_json(tail)
        if isinstance(extra, list):
            classes += [str(x) for x in extra if str(x) not in classes][:3]

    # 2) HUNT — one agent per attack class (discovery model)
    for cls in classes:
        run_stage(c, rid, name, path, "hunt", cls, disc, "discovery",
                  prompt_file("hunt.md"),
                  f"Attack class: {cls}\nRepo: {name}\n\nSOURCE:\n{src[:60000]}")

    # 3) VALIDATE — different model, tries to disprove every finding
    findings = []
    for st, cl, out in c.execute("SELECT stage, cls, output FROM tasks "
                                 "WHERE run_id=? AND repo=? AND stage='hunt'",
                                 (rid, name)):
        f = extract_json(out or "")
        if isinstance(f, list):
            findings += [x for x in f if isinstance(x, dict)]
    mech_ok, mech_bad = mechanical_check(findings, path)
    for f in mech_ok:
        run_stage(c, rid, name, path, "validate",
                  f['file'] + ':' + str(f['line']), vali, "validation",
                  prompt_file("validate.md"),
                  f"Try to DISPROVE this finding. Reply JSON "
                  f"{{\"verdict\":\"confirmed|refuted\",\"reason\":\"...\"}}.\n"
                  f"FINDING: {json.dumps(f)}\n\nSOURCE:\n{src[:60000]}")

    # 4) REPORT — pure script, no model
    confirmed = []
    for (out,) in c.execute("SELECT output FROM tasks WHERE run_id=? AND "
                            "repo=? AND stage='validate'", (rid, name)):
        v = extract_json(out or "")
        if isinstance(v, dict) and v.get("verdict") == "confirmed":
            confirmed.append(v)
    with open(f"report-{rid}.json", "w") as fh:
        json.dump({"run": rid, "repo": name, "hunt_findings": len(findings),
                   "mechanical_pass": len(mech_ok),
                   "mechanical_fail": len(mech_bad),
                   "confirmed": confirmed}, fh, indent=1)
    print(f"[{rid}] done: {len(findings)} raw, {len(mech_ok)} passed "
          f"mechanical check, {len(confirmed)} confirmed after validation")
    c.execute("UPDATE runs SET status='done' WHERE run_id=?", (rid,))
    c.commit()


if __name__ == "__main__":
    main()
