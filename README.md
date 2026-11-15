# vuln-harness

Fleet-wide vulnerability harness for khaalidrafi/* — a concrete implementation of
the architecture in https://blog.cloudflare.com/build-your-own-vulnerability-harness/
(Project Glasswing follow-up), adapted to our fleet.

## Architecture (mapped to the blog)

| Blog concept | Here |
| --- | --- |
| Not standalone models/prompts — an orchestration layer | `vh.py` orchestrator: discovery, validation, ledger, queue, report |
| Cross-check with distinct logic sets | discovery scanners (regex/format rules) vs an INDEPENDENT validation stage (exact-format, entropy, path-context heuristics) — different rule bases by design |
| Look beyond isolated repos | cross-repo blast radius: identical secret fingerprints found in multiple repos are grouped (`value_fp` = sha256(value)[:16]) |
| Thousands of candidates → trusted triaged queue | `state/queue.jsonl` holds confirmed findings only, sorted by severity; uncertain ones land in "needs review" |
| Investigations survive across runs | findings ledger `state/findings.json` with stable fingerprints; reruns merge/dedupe, never lose history |
| Continuous scanning | `.github/workflows/nightly.yml` (cron 01:30 UTC + manual dispatch) |

## SECRET LAW

Raw secret values are NEVER stored, logged, or printed — every candidate value is
reduced to a `sha256[:16]` fingerprint the moment it is found. Reports show the
fingerprint, path, rule, and severity only. Anyone holding the original value can
recompute the fingerprint to correlate; no one can reverse it.

## What v1 detects

- **Secrets**: AWS keys, GitHub PATs, OpenAI/Anthropic/Google AI keys, Slack and
  Telegram tokens, private key blocks, JWTs, basic-auth URLs, generic
  credential-shaped assignments.
- **CI hygiene**: third-party Actions not pinned to a commit SHA,
  `pull_request_target` + untrusted PR-head checkout, `curl | bash` in runners.
- **Web/config**: tracked `.env`/`.dev.vars`, secret-shaped `wrangler` vars,
  stale `compatibility_date` (> 2y), static dirs missing `_headers` (CSP/HSTS).
- **Dependencies**: unpinned `requirements.txt`, `FROM ...:latest` Dockerfiles.

Validation marks findings `confirmed`, `needs-review`, or
`false-positive(test-path)`; only confirmed findings enter the triage queue.
The `vault` repo is scanned with a by-design note (it IS the secret store).

## Run it

```bash
python3 vh.py scan <repo-dir>... --state state/   # scan (merges into ledger)
python3 vh.py report --state state/ --out report.md
```

## v2 — CI-only audits + two-model LLM stages (2026-11-12, master order)

**Audits run via GitHub CI only, never in the dev sandbox.** The fleet is
public, so the nightly workflow now lists + clones all repos tokenlessly
(`AUDIT_TOKEN` optional). Runs on: nightly cron 01:30 UTC, every push to
`main`, and manual dispatch. Results go to a 30-day ARTIFACT (`audit-fleet`:
`state/` + `report.md`), not commits (commit-hygiene law).

**Multi-model law (the blog's core point):** v1 cross-checked findings with
two independent static rule-sets. v2 adds the real LLM lane —
`harness/orchestrator.py` runs Recon -> Hunt (one agent per attack class,
`HARNESS_DISCOVERY_MODEL`) -> adversarial Validate (`HARNESS_VALIDATION_MODEL`,
a DIFFERENT model) -> report. State in SQLite keyed `(run_id, repo, stage)`,
resumable; findings stream as they happen; in-band API errors hidden inside
200-OK bodies are classified as failures, not successes (the blog's trap).

**Manual LLM run:** Actions -> nightly-fleet-audit -> Run workflow -> tick
`run_llm`, set `repo`. Per-lane secrets `HARNESS_DISCOVERY_API_KEY` /
`HARNESS_VALIDATION_API_KEY` (+ optional `*_BASE_URL`; both fall back to
shared `HARNESS_API_KEY` / `HARNESS_BASE_URL`) — the two models may not
exist on one API. Vars `HARNESS_DISCOVERY_MODEL` /
`HARNESS_VALIDATION_MODEL`. Artifact: `llm-harness-report` (`harness.db` +
`report-*.json`). In CI, keys come from the khaalidrafi/vault API at run
time (see AGENTS.md `vault_secret`). **Circle CI fallback:** while GitHub
Actions is down, `.circleci/config.yml` runs the same security audit
(nightly fleet job + on-demand LLM job with `VAULT_READ_TOKEN` context).

Prompts live in `prompts/`: recon invents repo-specific attack classes on
top of the ~10 built-ins; hunters must cite an exact file:line (mechanical
checker rejects wrong lines); the validator may only confirm/refute — it
can never file new findings.

## Not covered (v3 slots)

- Deep git-history secret archaeology (current runs are shallow clones).
- CVE lookup against an advisory DB.
- Hunter execution sandbox (`unshare`), sibling forking, wishlist,
  cross-repo tracer — add per blog advice only when the pain is real.
