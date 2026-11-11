---
name: sksecurity
description: Secret leak detection, honest-claims gate for crypto wording, shallow phishing/prompt-injection screening, and post-quantum posture reports. Read-only, local, no network.
metadata: {"requires":{"bins":["sksecurity"]},"install":[{"id":"pipx","kind":"shell","command":"pipx install 'sksecurity'","bins":["sksecurity"],"label":"Install sksecurity (pipx)"}]}
---

# SKSecurity

Use this when you need to check text or files for leaked credentials, check docs for
crypto overclaims, screen a message for obvious phishing or injection, or report the
post-quantum posture of the SK estate. It does not scan code for vulnerabilities,
quarantine files, monitor processes or fetch threat intelligence (removed in 2.0).

Everything is read-only: no command moves, deletes or modifies the files it inspects.

## Commands

```bash
# Secrets (exit 1 when found; values are redacted in output)
sksecurity guard scan <path>             # file or directory
sksecurity guard staged                  # what git would commit
sksecurity guard text "<string>"         # a string
sksecurity guard install --repo .        # git pre-commit hook
sksecurity guard scan <path> --format json

# Honest-claims gate (exit 1 on a forbidden overclaim)
sksecurity claims scan .
sksecurity claims text "<string>"

# Screening (shallow regex heuristics; SAFE is not a guarantee)
sksecurity screen "<text>" [--sender a@b.c] [--subject "..."] [--format json]

# Post-quantum posture
sksecurity pqc-report [--static] [--format json]
sksecurity pqc-posture [--static]
sksecurity pqc-dashboard | pqc-snapshot | pqc-stacks
```

## When to use which

| Situation | Command |
|---|---|
| About to commit | `guard staged` |
| Reviewing a directory for committed credentials | `guard scan <dir>` |
| Writing or reviewing security docs | `claims scan .` |
| Untrusted text headed for an agent | `screen` (one weak signal, not a filter) |
| Asked "are we quantum-resistant?" | `pqc-report`, cite the per-surface result |

## Triage

- A `guard` finding is a location and a redacted match. Rotate the credential first,
  then remove it. Do not paste the secret value anywhere.
- A `claims` finding names the phrase and the honest replacement ("post-quantum",
  "quantum-resistant", cite FIPS 203/204/205). Fix the wording; do not allowlist real claims.
- `screen` misses plenty (for example a bare shortened link plus "verify your password"
  scores SAFE). Do not treat SAFE as clean.

## MCP

`sksecurity-mcp` (stdio) exposes `check_secrets` and `screen_input`.

## Notes

- Run tests only with a throwaway `HOME` (`tests/conftest.py` enforces it).
- `SK_STANDALONE=1` disables the optional skcapstone sk-alert adapter.
- Docs: `README.md`, `SOP.md`, `docs/ARCHITECTURE.md`.
