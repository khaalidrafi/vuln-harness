# HUMANS.md

A guide for human developers who did not write this code. Written
from a fresh read of the sources on 2026-11-18, per the Owner's
order that agents explain AI-developed codebases.

## What this is

vuln-harness is a fleet-wide vulnerability scanner for the
khaalidrafi GitHub org, built as a concrete implementation of the
architecture in Cloudflare's "build your own vulnerability harness"
blog post (Project Glasswing follow-up). It has two independent
lanes that share nothing but the target repos:

- Lane 1, static: `vh.py` (433 lines, Python 3 stdlib only). Four
  discovery scanners (secrets, CI workflow hygiene, web/config
  hygiene, dependency pinning) feed a validation stage that uses a
  deliberately different rule set. Results merge into a persistent
  ledger and a severity-sorted triage queue.
- Lane 2, LLM: `harness/orchestrator.py` (297 lines, stdlib only).
  A Recon agent writes a threat model, Hunter agents (one per
  attack class) find issues, a mechanical checker rejects findings
  with nonexistent lines, and a DIFFERENT validation model tries to
  disprove each finding. State lives in SQLite and runs are
  resumable.

The single most important rule in the repo is SECRET LAW: raw
secret values are never stored, logged, or printed. Every candidate
value is reduced to `sha256(value)[:16]` (called `value_fp`) the
moment it is found. The raw string exists only in memory during a
scan and is stripped before anything is persisted.

## Mental model

### Lane 1: vh.py

`python3 vh.py scan <repo-dir>... --state state/` runs the
pipeline:

1. Discovery (logic set A, high recall). Four functions each return
   finding dicts: `discover_secrets` (11 regex rules over every
   walkable text file), `discover_workflows` (GitHub Actions
   YAML), `discover_webconfig` (.env files, wrangler configs,
   static dirs), `discover_deps` (requirements.txt, Dockerfile).
2. Triage + validation (logic set B). `triage()` dedupes by
   `(repo, rule, path, value_fp, line)`, then `validate()`
   re-judges each finding with different logic: placeholder and
   variable-expansion patterns reject examples; exact-format
   secret rules (AWS keys, GitHub PATs, ...) confirm on shape
   alone; the broad `openai_key` rule needs a service prefix or at
   least 3 digits to confirm; heuristic rules land in
   needs-review. Findings under test/docs paths are demoted to
   false-positive(test-path), except private keys. The vault repo
   gets a by-design note.
3. Persistence. `cmd_scan` loads the existing ledger, drops every
   old entry for the repos just scanned, appends the validated
   findings, and writes `state/findings.json` plus
   `state/queue.jsonl` (confirmed findings only, sorted by
   severity). Reruns therefore replace per-repo, not duplicate.

`python3 vh.py report --state state/ --out report.md` renders the
ledger to Markdown: a per-repo severity table, confirmed findings
with fingerprints, needs-review and false-positive sections, and a
cross-repo blast radius map (`blast_radius()` groups identical
`value_fp` values found in more than one repo; structural rules
are excluded so only real secret values group).

### Lane 2: harness/orchestrator.py

`orchestrator.py run --repo <checkout> --name <repo>` executes:

1. Recon: one discovery-model call gets the repo source (truncated
   to 60,000 chars) and must reply with an architecture sketch, a
   threat model, and a `CLASSES:` line holding a JSON array of up
   to 3 repo-specific attack classes on top of the 11 built-ins.
2. Hunt: one discovery-model call per attack class. Hunters must
   emit a JSON array of findings, each citing an exact file + line.
3. Mechanical check: pure Python; a finding survives only if the
   cited file exists and the line number is in range.
4. Validate: one validation-model call per surviving finding (a
   different model by law, possibly a different API). The prompt
   forbids filing new findings; the reply is a JSON verdict.
5. Report: pure script; writes `report-<run-id>.json` with counts
   and confirmed verdicts.

Every stage writes to SQLite (`harness.db`) keyed
`(run_id, repo, stage, cls)`. `orchestrator.py resume --run-id`
re-enters the pipeline; stages already marked OK are skipped, so a
crash loses nothing.

The LLM call itself (`llm()`) is a minimal OpenAI-compatible
chat completion via urllib: temperature 0.2, 3 attempts with
exponential backoff, and a body-error classifier
(`classify_response`) that treats rate-limit/quota/auth text inside
a 200-OK response as a transient failure instead of a model reply.

### CI wiring

Audits run in CI only, never in a dev sandbox (master order
2026-11-12). `.github/workflows/nightly.yml` runs the fleet scan
nightly (cron 01:30 UTC), on every push to `main`, and on manual
dispatch; it clones all khaalidrafi repos tokenlessly, runs
`vh.py scan fleet/*` + `report`, and uploads `state/` and
`report.md` as a 30-day artifact. A second manual-only job
(`run_llm` + `repo` inputs) runs the LLM lane. Results are never
committed (commit-hygiene law). `.circleci/config.yml` mirrors the
audit as a fallback while GitHub Actions is down, pulling per-lane
API keys from the khaalidrafi/vault repo at run time.
`.github/workflows/probe.yml` is a trivial dispatch probe.

## Code map

| File / symbol | Role |
|---|---|
| `vh.py` | Lane 1 in one file: rules, scanners, validation, ledger, report. |
| `SECRET_RULES` (line 43) | 11 discovery regexes with severities (aws_key, github_pat, openai_key, anthropic_key, slack_token, telegram_bot, google_api, private_key, jwt, basic_auth_url, credential_assign). |
| `SKIP_DIRS` / `SKIP_FILE_PAT` / `SKIP_NAME` / `MAX_SCAN_BYTES` | Walk filters: vendor dirs, binary/asset suffixes, lockfiles, 2 MB per-file cap. |
| `CTX_TEST_PAT` | Marks paths under test/spec/docs/etc. as test-adjacent. |
| `fp` / `entropy` (79 / 83) | sha256[:16] fingerprint; Shannon entropy (entropy is defined but not currently called by any rule). |
| `discover_secrets` (102) | Per-file, per-line regex scan; NUL byte in the first 8 KB skips binaries; lines truncated to 4096 chars. |
| `discover_workflows` (142) | Actions YAML: pull_request_target + PR-head checkout, non-SHA-pinned third-party actions (actions/, github/, dependabot/ prefixes are trusted), curl-piped-to-shell. |
| `discover_webconfig` (183) | Tracked .env/.dev.vars (with/without real values), wrangler secret-shaped vars, stale compatibility_date (> 730 days), static dirs with index.html but no _headers. |
| `discover_deps` (241) | Unpinned requirements.txt lines, `FROM ...:latest` Dockerfile lines. |
| `validate` (274) | Logic set B: placeholder gate, exact-format confirms, openai_key digit/prefix gate, needs-review defaults. |
| `triage` (299) | Dedupe, test-path demotion, vault note, severity sort. |
| `blast_radius` (322) | value_fp groups across repos, structural rules excluded. |
| `cmd_scan` / `cmd_report` (334 / 364) | Ledger merge (replace-per-repo) and Markdown rendering. |
| `harness/orchestrator.py` | Lane 2: pipeline, SQLite state, LLM client. |
| `BUILTIN_CLASSES` (47) | The 11 built-in attack classes (hardcoded-secrets, command-injection, sql-injection, path-traversal, ssrf, unsafe-deserialization, auth-bypass, insecure-http-transport, dependency-confusion, log-injection, timing-side-channel). |
| `llm` / `lane_creds` / `classify_response` (99 / 84 / 74) | OpenAI-compatible call with retries; per-lane key/base resolution (`HARNESS_<LANE>_*` falls back to `HARNESS_*`); in-band error detection. |
| `read_source` (134) | Repo concatenation capped at 120,000 chars (`.git`, node_modules, vendor skipped); stages slice `src[:60000]`. |
| `run_stage` (162) | Skip-if-OK task execution + SQLite upsert; the resume mechanism. |
| `extract_json` (174) | Pulls the first balanced JSON object/array out of a model reply. |
| `mechanical_check` (193) | Schema-lite check: cited file must exist, line number in 1..len(lines). |
| `prompts/recon.md`, `prompts/hunt.md`, `prompts/validate.md` | The three agent prompts (system roles for the stages). |
| `.github/workflows/nightly.yml` | Fleet audit CI: cron + push + dispatch, artifacts, manual LLM job. |
| `.github/workflows/probe.yml` | Dispatch probe (echo probe-ok). |
| `.circleci/config.yml` | Circle CI fallback: nightly fleet job + on-demand LLM job with vault-sourced keys. |

## Core algorithms

Static validation split. Discovery optimizes recall (broad
regexes, e.g. any `sk-` string of 20+ chars); validation optimizes
precision with independent logic: the placeholder pattern rejects
`${...}`, `<UPPER>`, `[REDACTED`, and words like example/fake/
changeme; the openai_key rule confirms only with an `sk-proj-` /
`sk-svcacct-` prefix or at least 3 digits (the comment cites CSS
identifiers like `sk-bouncedelay-*` as the false positive being
filtered). This two-rule-set cross-check is the blog's core idea,
implemented statically in lane 1 and with two different models in
lane 2.

Fingerprinting and blast radius. `fp(value)` is
`sha256(value)[:16]`. Because the fingerprint is deterministic,
anyone holding the original value can recompute it and correlate;
nobody can invert it. `blast_radius` groups findings by identical
`value_fp` across repos, which is how a leaked credential used in
several repos is spotted as one incident rather than N.

Ledger merge. `cmd_scan` is replace-per-repo: previous findings for
each scanned repo name are dropped before the new validated set is
appended. Repo identity is either the explicit `--repo` argument
or the basename of each scanned directory. History for unscanned
repos is preserved, which is what makes the fleet ledger additive
across nightly runs.

Resumable LLM stages. The tasks table's primary key is
`(run_id, repo, stage, cls)` and `run_stage` returns immediately
when a matching row already has status OK. The hunt stage's task
key is the attack class; the validate stage's key is
`file:line` of the finding. Retries happen inside `llm()` (3
attempts, sleeps of 5, 10, 20 seconds) and in-band error bodies
are reclassified as TRANSIENT_ERROR, so a "successful" API call
that actually failed never poisons the pipeline with error text as
a finding.

## Invariants and gotchas

- SECRET LAW is enforced by discipline, not by types: `_raw` rides
  along in finding dicts during a scan and is popped twice in
  `cmd_scan` (once for the loaded ledger, once before the write).
  If you add a new persistence or logging path, you must pop
  `_raw` before it. This is the one law that overrides everything
  else.
- Workflow and web/config findings often carry `line: 0`
  (whole-file rules). `cmd_report` omits the `:line` suffix for
  zero lines; the queue keeps the field.
- The `entropy` function is defined but unused. Do not assume any
  rule gates on entropy; today only the placeholder regex and the
  openai_key digit/prefix check do precision work.
- Test-adjacent demotion happens after validation, on the relative
  path only. A real secret in a test fixture is reported as
  false-positive(test-path) unless it is a private key block.
  That is a deliberate recall trade, not a bug.
- Rescanning replaces per repo NAME. If two scanned directories
  share a basename, or a `--repo` name collides with another
  repo's name, the later scan clobbers the earlier findings for
  that name.
- `value_fp` for structural rules fingerprints the path or action
  string, not a secret. `blast_radius` explicitly skips those
  rules so its groups are always real values.
- `read_source` caps total repo context at 120,000 characters and
  each stage re-slices the same string to 60,000. Large repos are
  silently truncated; hunters only ever see the prefix in file
  walk order. Deep-history archaeology is out of scope (v3 slot;
  CI clones are shallow).
- `extract_json` tries only the first `[` or `{` opener in a reply
  and gives up if that bracket run does not parse. Model replies
  that open with prose containing an unbalanced bracket can lose
  their findings.
- The mechanical check verifies the line exists, not that the
  finding is at the right place. It is a floor, not a judge.
- No unit tests exist in this repo; CI (the fleet audit itself) is
  the only automated check. There is no Makefile. Lane 1 runs on
  any Python 3 with stdlib only.
- The two models in lane 2 must be different; `main()` refuses to
  start otherwise. The two lanes may also use different providers
  (per-lane BASE_URL), which is why credentials resolve per lane.
- AGENTS.md documents the vault key-fetch helper (`vault_secret`)
  used in CI. Never echo fetched values; the helper exists
  specifically to pipe them into env vars without printing.

## Developing

There is no build step and no test suite. The real commands are:

```bash
# Lane 1 (static, no keys, no models)
python3 vh.py scan <repo-dir>... --state state/
python3 vh.py report --state state/ --out report.md

# Lane 2 (LLM; needs two DIFFERENT models)
export HARNESS_DISCOVERY_MODEL=model-a
export HARNESS_VALIDATION_MODEL=model-b    # != model-a
python3 harness/orchestrator.py run --repo /path/to/checkout --name <repo>
python3 harness/orchestrator.py resume --run-id <id>   # after a crash
python3 harness/orchestrator.py report --run-id <id> --out report.md
```

Per-lane credentials: `HARNESS_DISCOVERY_API_KEY` /
`HARNESS_VALIDATION_API_KEY` (fall back to shared
`HARNESS_API_KEY`), plus optional `*_BASE_URL` (default
`https://api.openai.com/v1`). See AGENTS.md for the full runbook,
including the vault key-fetch helper and CI lane.

Branch law for this repo: the remote default branch is `main`.
AI work lands on `ai/main` and pushes there only; never push
`main`. Commit law (AGENTS.md): subject <= 72 chars, no
bookkeeping-only commits, both co-author trailers on every commit.
