# SKSecurity

[![CI](https://github.com/smilinTux/sksecurity/actions/workflows/ci.yml/badge.svg)](https://github.com/smilinTux/sksecurity/actions/workflows/ci.yml)

Small, local security tools for an AI agent estate. Four things ship:

| Tool | What it does | Honest limit |
|---|---|---|
| `guard` | Finds leaked credentials in files, directories, staged git changes and text. Redacts what it prints. | 12 regexes. Finds known token shapes and `key = "value"` assignments, nothing else. |
| `claims` | Fails on forbidden crypto overclaims in docs and code ("quantum-proof", "unbreakable"). Runs in CI. | Pattern match. Honest negations and quoted references are allowed. |
| `screen` | Scores text for phishing, prompt injection and social engineering. | Text-only regex heuristics. A SAFE verdict is not a guarantee. |
| `pqc-*` | Post-quantum self-report built from live skcomms / SKStacks data. | Reports what the registry says is deployed, per surface. |

Also in the package: `sksecurity.kms` (an HKDF + AES-GCM key-wrapping KMS that
`skcapstone` imports), an MCP server with two tools, and an optional sk-alert
adapter.

Everything is read-only with respect to the files it inspects. Nothing is moved,
deleted or modified, nothing runs in the background, and there are no network
calls. License: GPL-3.0-or-later.

2.0 removed the scanner, quarantine, dashboard, threat-intel feed and monitor
(see [CHANGELOG.md](CHANGELOG.md)). They did not work and one of them moved the
scanned directory.

## Install

```bash
pip install sksecurity            # CLI: sksecurity, MCP server: sksecurity-mcp
pip install 'sksecurity[skcapstone]'   # optional: publish alerts on sk-alert
```

## Examples

Output below was produced by running the commands against a throwaway directory
with a temporary `HOME`.

### guard: find secrets

```console
$ sksecurity guard scan demo
🔐 SKSecurity Secret Guard Report
==================================================
📁 Target: demo
📄 Files Scanned: 1

🚨 Found 1 secret(s):
------------------------------
  🟠 PostgreSQL Connection String
     File: demo/settings.py:3
     Match: post********************app"
     PostgreSQL connection string with credentials
     Fix: Change the database password. Use environment variables.
$ echo $?
1
```

Other forms: `guard staged` (what would be committed), `guard text "..."`,
`guard install` (git pre-commit hook), `--format json`. Exit code is 1 when
secrets are found.

### claims: block overclaims

```console
$ sksecurity claims text "our link is quantum-proof"
🚨 Found 1 overclaim(s):
  🔴 quantum-proof: quantum-proof
     Say: Say "post-quantum" / "quantum-resistant" and cite FIPS 203/204.
$ echo $?
1
```

`sksecurity claims scan .` is the CI gate (`.github/workflows/honest-claims.yml`).
Suppress an honest reference with `# honest-claims: allow` or list a file in
`.honestclaims-allow`.

### screen: heuristic input screening

```console
$ sksecurity screen "Your account is suspended. Verify your password at http://paypa1-login.tk/verify" --subject "Urgent: account suspended"
🛡️ SKSecurity Email/Input Screening Report
==================================================
📊 Risk Score: 59.2/100
🎯 Verdict: SUSPICIOUS

🚨 Found 1 issue(s):
------------------------------
  🟠 [HIGH] malicious_link
     Suspicious URL: suspicious TLD (.tk), phishing keyword in domain (login)
     Match: "http://paypa1-login.tk/verify"
     Fix: Do not follow this link. Verify with the sender through a trusted channel.
```

It misses things. `click http://bit.ly/x to verify your password now` with subject
`Urgent` scores 0 and SAFE. Treat it as one weak signal, not a filter.

### pqc-*: post-quantum posture

`pqc-report`, `pqc-posture`, `pqc-dashboard`, `pqc-snapshot` and `pqc-stacks`
print a per-surface table (`hybrid-pq`, `gated`, `classical`, `symmetric`) with
FIPS references and honest notes. `--static` shows the model defaults instead of
live fleet state. `pqc-stacks` needs SKStacks at `~/clawd/SKStacks` or
`SKSTACKS_ROOT`. `capauth` imports `sksecurity.pqc_report`.

```console
$ sksecurity pqc-posture --static
🔐 PQC Posture - coverage self-report (per surface)
======================================================================
Mode: static   (honest claims only - hybrid = either-leg; no overclaims)

surface       posture    wire-tag                   suite
----------------------------------------------------------------------
dm-ratchet    gated      pqdr1                      x25519-pgp-wrap-v1 → x25519-mlkem768
group         gated      kem_suite                  rsa-pgp-wrap-v1 → x25519-mlkem768
...
transport     classical  channel: WireGuard/TLS X25519 wireguard-x25519 / tls1.3-x25519
```

## MCP server

`sksecurity-mcp` speaks stdio and exposes two tools:

- `check_secrets`: run the secret guard on text.
- `screen_input`: run the email/input screener on text (optional `sender`, `subject`).

```json
{"mcpServers": {"sksecurity": {"command": "sksecurity-mcp"}}}
```

## Library use

```python
from sksecurity import SecretGuard, EmailScreener
from sksecurity.honest_claims import HonestClaimsScanner
from sksecurity.kms import KMS            # used by skcapstone
from sksecurity.pqc_report import build_live_report   # used by capauth
```

## Development

```bash
pip install -e '.[dev]'
pytest
ruff check sksecurity/
```

The test suite points `HOME` and `SKCAPSTONE_HOME` at tmp dirs and sets
`SK_STANDALONE=1` (`tests/conftest.py`), so it never touches real state. Keep
doing that if you run tests some other way.

See [SOP.md](SOP.md) for operations, [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
for the module map, [docs/QUANTUM_RESISTANCE.md](docs/QUANTUM_RESISTANCE.md) for the
PQC inventory, [SECURITY.md](SECURITY.md) to report a vulnerability, and
[CONTRIBUTING.md](CONTRIBUTING.md).
