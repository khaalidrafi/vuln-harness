# AGENTS.md — how to run a security audit with this harness

Any agent (lead, slave, fresh session) can perform a security audit of
any repo with this harness. Two lanes, run both when you can.

## Lane 1 — static security audit (no keys, no models)

```bash
git clone https://github.com/khaalidrafi/vuln-harness
git clone https://github.com/<owner>/<target>.git target
cd vuln-harness
python3 vh.py scan ../target --state state/
python3 vh.py report --state state/ --out report.md
```

Report back every CRITICAL/HIGH finding with file:line and rule id.

LAW (read before reporting):
- NEVER print, store or forward raw secret values — the harness only
  emits `value_fp` sha256[:16] fingerprints; keep it that way.
- Report only confirmed findings; `needs-review` items are listed
  separately in the report.

## Lane 2 — LLM security audit (two-model law)

Discovery and validation MUST use two DIFFERENT models (one model, one
lens — the CF-blog core point). The models may not exist on one API, so
each lane carries its OWN key and base URL (both optional: unset lanes
fall back to the shared HARNESS_API_KEY / HARNESS_BASE_URL):

```bash
export HARNESS_DISCOVERY_MODEL=model-a
export HARNESS_DISCOVERY_BASE_URL=https://provider-a/v1
export HARNESS_DISCOVERY_API_KEY=...

export HARNESS_VALIDATION_MODEL=model-b          # != model-a
export HARNESS_VALIDATION_BASE_URL=https://provider-b/v1
export HARNESS_VALIDATION_API_KEY=...

python3 harness/orchestrator.py run --repo ../target --name <target>
# after a crash, nothing is lost (SQLite state, resumable):
python3 harness/orchestrator.py resume --run-id <id>
```

Security-audit pipeline: Recon (writes architecture.md + threat model,
may invent repo-specific attack classes) -> Hunt (one agent per class,
must cite exact file:line) -> mechanical check (line must exist) ->
Validate (different model tries to DISPROVE; can never file new
findings) -> report-<run>.json.

## Getting keys — khaalidrafi/vault API

The vault is the secret store (one file per name under `secrets/`).
Read a value through the GitHub contents API with a token that can see
the private repo — and NEVER echo it:

```bash
vault_secret() {  # usage: vault_secret ZAI_API_KEY
  curl -sf -H "Authorization: Bearer $VAULT_READ_TOKEN" \
    "https://api.github.com/repos/khaalidrafi/vault/contents/secrets/$1" \
    | python3 -c "import base64,json,sys;print(base64.b64decode(json.load(sys.stdin)['content']).decode(),end='')"
}
export HARNESS_DISCOVERY_API_KEY="$(vault_secret ZAI_API_KEY)"
export HARNESS_VALIDATION_API_KEY="$(vault_secret OPENROUTER_API_KEY)"
```

Held key names live in the vault's `secrets/README.md` index. Values
never appear in chat, logs, commits or artifacts (SECRET LAW).

## CI lane (master order 2026-11-12: audits run in CI, never a sandbox)

- **GitHub Actions** (primary): `nightly-fleet-audit` — nightly cron
  01:30 UTC, every push to main, manual dispatch. Artifacts
  `audit-fleet` / `llm-harness-report`; never commits.
- **Circle CI** (fallback while GitHub Actions is down): see
  `.circleci/config.yml` — same security audit, keys pulled from the
  vault API at run time via the `VAULT_READ_TOKEN` context variable.

## Commit law (if you change this repo)

Author `GLM-5.3-Flash <glm-5.3-flash@z.ai>`, trailers
`Co-authored-by: z.ai-agent <noreply@z.ai>` and
`Co-authored-by: Khalid Rafi <khaalidrafi@gmail.com>`, subject <= 72
chars, no bookkeeping-only commits.
