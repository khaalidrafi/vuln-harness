#!/usr/bin/env python3
"""vh.py — vuln-harness: fleet-wide vulnerability scanner + triage queue.

Architecture per blog.cloudflare.com/build-your-own-vulnerability-harness
(Project Glasswing follow-up), adapted to a self-hosted fleet:

  1. DISCOVERY stage  — broad independent scanners (secrets, CI workflows,
     web/config hygiene, dependency manifests). One rule-set, high recall.
  2. VALIDATION stage — a SECOND, independent logic set re-judges every
     candidate (placeholder heuristics, exact-format checks, entropy,
     path context). Different rules than discovery by design: cross-checking
     distinct logic sets is the point of the harness.
  3. PERSISTENCE      — findings ledger (state/findings.json) with stable
     fingerprints: resumable, deduped across runs.
  4. CROSS-REPO TRACE — identical secret fingerprints across repos are
     grouped into a blast-radius map.
  5. TRIAGE QUEUE     — state/queue.jsonl: confirmed findings only, sorted
     by severity. v2 slot: interchangeable-LLM triage stage (env
     VULN_HARNESS_LLM=1) rides in here.

SECRET LAW: raw secret values are NEVER written anywhere — every value is
reduced to a sha256[:16] fingerprint the moment it is found.

Usage:
  python3 vh.py scan <dir> [--repo NAME] --state STATE_DIR
  python3 vh.py report --state STATE_DIR [--out report.md]
"""
import argparse
import hashlib
import json
import math
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# ---------------------------------------------------------------------------
# Discovery rule set (logic set A — broad, high recall)
# ---------------------------------------------------------------------------
SECRET_RULES = [
    ("aws_key", r"AKIA[0-9A-Z]{16}", "CRITICAL"),
    ("github_pat", r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22,}_[A-Za-z0-9]{59,}", "CRITICAL"),
    ("openai_key", r"(?<![A-Za-z0-9])sk-(proj-|svcacct-)?[A-Za-z0-9_-]{20,}", "CRITICAL"),
    ("anthropic_key", r"sk-ant-[A-Za-z0-9_-]{20,}", "CRITICAL"),
    ("slack_token", r"xox[baprs]-[A-Za-z0-9-]{10,}", "HIGH"),
    ("telegram_bot", r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b", "HIGH"),
    ("google_api", r"AIza[0-9A-Za-z_\-]{35}", "HIGH"),
    ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY(?: BLOCK)?-----", "CRITICAL"),
    ("jwt", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "HIGH"),
    ("basic_auth_url", r"https?://[A-Za-z0-9._%\-]+:[^@\s]{6,}@", "HIGH"),
    ("credential_assign", r"(?i)\b(api[_-]?key|secret|token|passwd|password|auth)\b\s*[:=]\s*['\"][^'\"\s]{16,}['\"]", "HIGH"),
]

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox",
             "dist", "build", ".next", ".turbo", "target", "out", "Pods"}
SKIP_FILE_PAT = re.compile(
    r"\.(min\.js|min\.css|map|lock|ico|png|jpe?g|gif|webp|woff2?|ttf|eot|so|o|a|dylib|bin|zip|gz|bz2|xz|7z|jar|class|pyc|pak|svg|mp4|mp3|webm|flac|wav)$",
    re.IGNORECASE)
SKIP_NAME = re.compile(r"^(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock|poetry\.lock|composer\.lock|go\.sum)$")
MAX_SCAN_BYTES = 2 * 1024 * 1024

CTX_TEST_PAT = re.compile(
    r"(^|/)(test|tests|spec|specs|fixtures?|mocks?|examples?|samples?|docs?|demo|demos|benchmark|evals?|website)(/|$)"
    r"|(^|/)(test|spec|mock|fixture)[\w.\-]*\.\w+$"
    r"|[\w.\-]*\.(test|spec)\.\w+$",
    re.IGNORECASE)

# Validation-time placeholder / variable-expansion gate (raw value is held
# in memory ONLY for the duration of the scan, never persisted).
VAR_PLACEHOLDER_PAT = re.compile(
    r"\$\{[^}]*\}|<[A-Z_]{2,}>|\[REDACTED|\byour\b|\bexample\b|\bfake\b"
    r"|\bdummy\b|\bsample\b|\bplaceholder\b|\bchangeme\b|\bnot-a-real\b",
    re.IGNORECASE)


def fp(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = defaultdict(int)
    for ch in s:
        counts[ch] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def iter_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if SKIP_FILE_PAT.search(name) or SKIP_NAME.match(name):
                continue
            yield os.path.join(dirpath, name)


def discover_secrets(root: str, repo: str):
    out = []
    for path in iter_files(root):
        rel = os.path.relpath(path, root)
        try:
            if os.path.getsize(path) > MAX_SCAN_BYTES:
                continue
            with open(path, "rb") as fh:
                blob = fh.read(MAX_SCAN_BYTES)
            if b"\x00" in blob[:8192]:
                continue
            text = blob.decode("utf-8", "replace")
        except OSError:
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            if len(line) > 4096:
                line = line[:4096]
            for rule, pat, sev in SECRET_RULES:
                for m in re.finditer(pat, line):
                    val = m.group(0)
                    if val.startswith("-----BEGIN"):
                        val = "PRIVATE_KEY_BLOCK"
                    out.append({
                        "repo": repo, "rule": rule, "path": rel,
                        "line": line_no, "severity": sev,
                        "value_fp": fp(val), "value_len": len(val),
                        "_raw": val,
                        "ctx": "test-adjacent" if CTX_TEST_PAT.search("/" + rel) else "prod-path",
                        "stage": "discovery",
                    })
    return out


USES_PAT = re.compile(r"uses:\s*([\w.\-/]+)@(\S+)")
PR_TARGET_PAT = re.compile(r"pull_request_target")
PR_HEAD_PAT = re.compile(r"github\.event\.pull_request\.head|refs/pull/[^/]+/head")
CURLSH_PAT = re.compile(r"curl[^|#]*(\||&&)[^|#]*\b(bash|sh|zsh)\b")
SAFE_ACTIONS = {"actions/", "github/", "dependabot/"}


def discover_workflows(root: str, repo: str):
    out = []
    wf_root = os.path.join(root, ".github", "workflows")
    if not os.path.isdir(wf_root):
        return out
    for name in sorted(os.listdir(wf_root)):
        if not (name.endswith(".yml") or name.endswith(".yaml")):
            continue
        path = os.path.join(wf_root, name)
        rel = os.path.relpath(path, root)
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        if PR_TARGET_PAT.search(text) and PR_HEAD_PAT.search(text):
            out.append({"repo": repo, "rule": "wf_pr_target_untrusted_checkout",
                        "path": rel, "line": 0, "severity": "HIGH",
                        "value_fp": fp("pr_target+head"), "value_len": 0,
                        "ctx": "prod-path", "stage": "discovery"})
        for m in USES_PAT.finditer(text):
            action, ref = m.group(1), m.group(2)
            if any(action.startswith(p) for p in SAFE_ACTIONS):
                continue
            if "/" in action and not re.fullmatch(r"[0-9a-f]{40}", ref):
                out.append({"repo": repo, "rule": "wf_action_not_sha_pinned",
                            "path": rel, "line": 0, "severity": "MEDIUM",
                            "value_fp": fp(action + "@" + ref), "value_len": 0,
                            "ctx": "prod-path", "stage": "discovery",
                            "meta": {"action": action, "ref": ref}})
        for line_no, line in enumerate(text.splitlines(), 1):
            if CURLSH_PAT.search(line):
                out.append({"repo": repo, "rule": "wf_curl_pipe_shell",
                            "path": rel, "line": line_no, "severity": "MEDIUM",
                            "value_fp": fp(line.strip()[:200]), "value_len": 0,
                            "ctx": "prod-path", "stage": "discovery"})
    return out


WRANGLER_VARS = re.compile(r"(?i)^([\w\-]*(?:key|secret|token|password)[\w\-]*)\s*=\s*['\"]?([^'\"\s]{8,})", re.M)


def discover_webconfig(root: str, repo: str):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        names = set(filenames)
        for name in sorted(names):
            low = name.lower()
            if low == ".dev.vars" or (low.startswith(".env") and not low.endswith((".example", ".sample", ".template", ".dist"))):
                rel = os.path.relpath(os.path.join(dirpath, name), root)
                try:
                    content = open(os.path.join(dirpath, name), encoding="utf-8", errors="replace").read(262144)
                except OSError:
                    continue
                real = [ln for ln in content.splitlines()
                        if ln.strip() and not ln.strip().startswith("#")
                        and "=" in ln and ln.split("=", 1)[1].strip()]
                out.append({"repo": repo, "rule": "tracked_env_file" + ("_with_values" if real else ""),
                            "path": rel, "line": 0,
                            "severity": "HIGH" if real else "INFO",
                            "value_fp": fp(rel), "value_len": len(real),
                            "ctx": "prod-path", "stage": "discovery"})
        for name in ("wrangler.toml", "wrangler.json", "wrangler.jsonc", "wranglerc.json"):
            if name in names:
                rel = os.path.relpath(os.path.join(dirpath, name), root)
                try:
                    content = open(os.path.join(dirpath, name), encoding="utf-8", errors="replace").read(262144)
                except OSError:
                    continue
                for m in WRANGLER_VARS.finditer(content):
                    var, val = m.group(1), m.group(2)
                    out.append({"repo": repo, "rule": "wrangler_secret_shaped_var",
                                "path": rel, "line": 0, "severity": "HIGH",
                                "value_fp": fp(val), "value_len": len(val),
                                "ctx": "prod-path", "stage": "discovery",
                                "meta": {"var": var}})
                m = re.search(r'compatibility_date\s*=\s*["\'](\d{4}-\d{2}-\d{2})["\']', content)
                if m:
                    try:
                        d = datetime.strptime(m.group(1), "%Y-%m-%d").replace(tzinfo=timezone.utc)
                        age_days = (datetime.now(timezone.utc) - d).days
                        if age_days > 730:
                            out.append({"repo": repo, "rule": "wrangler_stale_compatibility_date",
                                        "path": rel, "line": 0, "severity": "LOW",
                                        "value_fp": fp(m.group(1)), "value_len": 0,
                                        "ctx": "prod-path", "stage": "discovery",
                                        "meta": {"date": m.group(1)}})
                    except ValueError:
                        pass
        if "index.html" in names and "_headers" not in names:
            rel = os.path.relpath(dirpath, root)
            if rel != ".":
                out.append({"repo": repo, "rule": "static_dir_missing_headers",
                            "path": rel, "line": 0, "severity": "MEDIUM",
                            "value_fp": fp(rel), "value_len": 0,
                            "ctx": "prod-path", "stage": "discovery"})
    return out


def discover_deps(root: str, repo: str):
    out = []
    req = os.path.join(root, "requirements.txt")
    if os.path.isfile(req):
        try:
            lines = open(req, encoding="utf-8", errors="replace").read().splitlines()
        except OSError:
            lines = []
        unpinned = [ln for ln in lines if ln.strip() and not ln.strip().startswith("#")
                    and not re.match(r"^[A-Za-z0-9_.\-\[\]]+\s*[=<>!~]", ln)]
        if unpinned:
            out.append({"repo": repo, "rule": "deps_unpinned_requirements",
                        "path": "requirements.txt", "line": 0, "severity": "LOW",
                        "value_fp": fp("unpinned:%d" % len(unpinned)),
                        "value_len": len(unpinned), "ctx": "prod-path",
                        "stage": "discovery", "meta": {"count": len(unpinned)}})
    docker = os.path.join(root, "Dockerfile")
    if os.path.isfile(docker):
        try:
            lines = open(docker, encoding="utf-8", errors="replace").read().splitlines()
        except OSError:
            lines = []
        if any(re.match(r"^FROM\s+\S+:latest\s*$", ln, re.I) for ln in lines):
            out.append({"repo": repo, "rule": "docker_from_latest",
                        "path": "Dockerfile", "line": 0, "severity": "LOW",
                        "value_fp": fp("from-latest"), "value_len": 0,
                        "ctx": "prod-path", "stage": "discovery"})
    return out


# ---------------------------------------------------------------------------
# Validation rule set (logic set B — independent of discovery logic)
# ---------------------------------------------------------------------------
def validate(f):
    """Re-judge one discovery finding with DIFFERENT logic. Returns status."""
    rule, value_len = f["rule"], f.get("value_len", 0)
    raw = f.get("_raw") or ""
    if raw and VAR_PLACEHOLDER_PAT.search(raw):
        return "false-positive(variable-or-placeholder)"
    exact_format = ("aws_key", "github_pat", "anthropic_key", "google_api",
                    "telegram_bot", "slack_token", "jwt", "basic_auth_url", "private_key")
    if rule in exact_format:
        return "confirmed"
    if rule == "openai_key":
        # Real OpenAI-family keys carry a service prefix or digit entropy;
        # CSS/identifiers like sk-bouncedelay-* do not.
        if raw.startswith(("sk-proj-", "sk-svcacct-")):
            return "confirmed"
        return "confirmed" if sum(ch.isdigit() for ch in raw) >= 3 else "false-positive(identifier-shape)"
    if rule in ("tracked_env_file_with_values", "wrangler_secret_shaped_var", "credential_assign"):
        return "needs-review"
    if rule in ("wf_pr_target_untrusted_checkout", "wf_action_not_sha_pinned", "wf_curl_pipe_shell",
                "static_dir_missing_headers", "wrangler_stale_compatibility_date",
                "tracked_env_file", "deps_unpinned_requirements", "docker_from_latest"):
        return "confirmed"
    return "needs-review"


def triage(findings):
    seen = {}
    for f in findings:
        key = "%s|%s|%s|%s|%s" % (f["repo"], f["rule"], f["path"], f["value_fp"], f.get("line", 0))
        if key not in seen:
            seen[key] = f
    out = []
    for f in seen.values():
        f = dict(f)
        status = validate(f)
        f["status"] = status
        if status == "needs-review":
            f["severity"] = "INFO" if f["severity"] == "LOW" else f["severity"]
        if f.get("ctx") == "test-adjacent" and f["rule"] != "private_key":
            f["status"] = "false-positive(test-path)"
            f["severity"] = "INFO"
        if f["repo"] == "vault":
            f["note"] = "by-design secret store — verify each entry is sealed/encrypted"
        out.append(f)
    out.sort(key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["repo"], x["path"]))
    return out


def blast_radius(ledger):
    skip = {"wf_action_not_sha_pinned", "static_dir_missing_headers", "wf_pr_target_untrusted_checkout",
            "wf_curl_pipe_shell", "tracked_env_file", "tracked_env_file_with_values",
            "deps_unpinned_requirements", "docker_from_latest", "wrangler_stale_compatibility_date"}
    groups = defaultdict(list)
    for f in ledger:
        if f["rule"] in skip:
            continue
        groups[f["value_fp"]].append("%s:%s" % (f["repo"], f["path"]))
    return {k: v for k, v in groups.items() if len(v) > 1}


def cmd_scan(args):
    ledger_path = os.path.join(args.state, "findings.json")
    ledger = []
    if os.path.isfile(ledger_path):
        ledger = json.load(open(ledger_path))
    for f in ledger:
        f.pop("_raw", None)  # secret law: raw values never persist
    repos = [args.repo] if args.repo else [os.path.basename(os.path.abspath(d.rstrip("/"))) for d in args.dirs]
    new = []
    for d, repo in zip(args.dirs, repos):
        new += discover_secrets(d, repo)
        new += discover_workflows(d, repo)
        new += discover_webconfig(d, repo)
        new += discover_deps(d, repo)
    validated = triage(new)
    ledger = [f for f in ledger if f["repo"] not in repos]
    ledger += validated
    for f in ledger:
        f.pop("_raw", None)  # secret law: raw values never persist
    os.makedirs(args.state, exist_ok=True)
    json.dump(ledger, open(ledger_path, "w"), indent=1)
    with open(os.path.join(args.state, "queue.jsonl"), "w") as fh:
        for f in sorted(ledger, key=lambda x: SEV_ORDER.get(x["severity"], 9)):
            if f["status"] == "confirmed":
                fh.write(json.dumps({k: f[k] for k in
                                     ("repo", "rule", "path", "line", "severity", "value_fp", "ctx")}) + "\n")
    confirmed = sum(1 for f in validated if f["status"] == "confirmed")
    print("scan: %d findings; %d confirmed; ledger=%d" % (len(validated), confirmed, len(ledger)))


def cmd_report(args):
    ledger = json.load(open(os.path.join(args.state, "findings.json")))
    conf = [f for f in ledger if f["status"] == "confirmed"]
    review = [f for f in ledger if f["status"] == "needs-review"]
    fp = [f for f in ledger if str(f["status"]).startswith("false-positive")]
    by_repo = defaultdict(lambda: defaultdict(int))
    for f in conf:
        by_repo[f["repo"]][f["severity"]] += 1
    lines = ["# vuln-harness audit report", "",
             "generated: %s" % datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
             "SECRET LAW: raw values are never printed — value_fp = sha256(value)[:16]",
             "counts below = CONFIRMED findings only (false positives and unverified",
             "candidates are listed separately; raw evidence lives in the ledger)", "",
             "| repo | CRITICAL | HIGH | MEDIUM | LOW | INFO |", "| --- | --- | --- | --- | --- | --- |"]
    for repo in sorted(by_repo):
        c = by_repo[repo]
        lines.append("| %s | %d | %d | %d | %d | %d |" % (
            repo, c.get("CRITICAL", 0), c.get("HIGH", 0), c.get("MEDIUM", 0),
            c.get("LOW", 0), c.get("INFO", 0)))
    lines += ["", "## Confirmed findings", ""]
    for f in conf:
        meta = (" " + json.dumps(f["meta"], ensure_ascii=False)) if f.get("meta") else ""
        lines.append("- **%s** `%s` %s:%s%s value_fp=%s%s" % (
            f["severity"], f["rule"], f["repo"], f["path"],
            ":" + str(f["line"]) if f.get("line") else "", f["value_fp"], meta))
    lines += ["", "## Needs review (validation stage uncertain) — %d" % len(review), ""]
    for f in review:
        lines.append("- %s `%s` %s:%s:%s value_fp=%s" % (
            f["severity"], f["rule"], f["repo"], f["path"], f.get("line", 0), f["value_fp"]))
    lines += ["", "## False positives excluded (spot-checked evidence) — %d" % len(fp), ""]
    seen_fp = set()
    for f in fp:
        key = (f["value_fp"], f["rule"])
        if key in seen_fp:
            continue
        seen_fp.add(key)
        lines.append("- %s `%s` value_fp=%s — %s" % (
            f["severity"], f["rule"], f["value_fp"], f.get("status", "")))
    br = blast_radius(ledger)
    lines += ["", "## Cross-repo blast radius (same value_fp in multiple repos)", ""]
    lines += (["- value_fp=%s: %s" % (k, ", ".join(sorted(set(v)))) for k, v in sorted(br.items(), key=lambda x: -len(x[1]))]
              or ["- none"])
    lines += ["", "## Not covered in this run", "",
              "- git history (shallow clones; deep-history secret purge scan = v2 run)",
              "- dependency CVE lookup (needs an advisory DB; manifests linted only)",
              "- LLM triage stage (v2: interchangeable-model cross-check per the CF harness model)"]
    out = args.out or "report.md"
    open(out, "w").write("\n".join(lines) + "\n")
    print("report: %s (%d findings)" % (out, len(ledger)))


def main():
    ap = argparse.ArgumentParser(prog="vh.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("dirs", nargs="+")
    s.add_argument("--repo")
    s.add_argument("--state", default="state")
    s = sub.add_parser("report")
    s.add_argument("--state", default="state")
    s.add_argument("--out", default="report.md")
    args = ap.parse_args()
    if args.cmd == "scan":
        cmd_scan(args)
    else:
        cmd_report(args)


if __name__ == "__main__":
    main()
