# SKSecurity Architecture

What ships in 2.0: a small Python package with a CLI, an MCP server, and a few
library modules that other SK packages import. Nothing runs in the background,
nothing is scheduled by the package, and nothing leaves the host.

## Modules

| Module | What it does | Entry points |
|---|---|---|
| `secret_guard.py` | 12 regexes for credentials (cloud keys, tokens, PEM headers, passwords in assignments, DSNs). Redacts matches, skips `.git` and virtualenvs, has a git pre-commit hook installer. | `sksecurity guard {scan,staged,install,text}`, MCP `check_secrets`, `SecretGuard` |
| `honest_claims.py` | The no-overclaim gate: flags "quantum-proof", "unbreakable" and similar, allows honest negations and quoted references. | `sksecurity claims {scan,text}`, CI workflow `honest-claims.yml` |
| `email_screener.py` | Text-only regex heuristics for phishing, prompt injection and social engineering, with a 0-100 score and a verdict. Shallow: a SAFE verdict is not a guarantee. | `sksecurity screen`, MCP `screen_input`, `EmailScreener` |
| `pqc_report.py`, `pqc_posture.py`, `pqc_stacks.py` | Post-quantum self-report built from live data (the skcomms suite registry and group state, SKStacks descriptors) with an embedded fallback. | `sksecurity pqc-{report,posture,dashboard,snapshot,stacks}`; `capauth` imports `pqc_report` |
| `kms.py` | HKDF + AES-GCM key-wrapping KMS with a 4-tier key hierarchy. Imported by `skcapstone.kms`. | library only |
| `integration.py` | Optional publishing to the sk-alert bus when `skcapstone` is importable and `SK_STANDALONE` is unset. Otherwise logs locally. It never registers the service, never writes scheduler jobs, never touches the skcapstone registry. | `alert()`, `is_present()`, `level_for_severity()` |
| `mcp_server.py` | stdio MCP server with two tools: `check_secrets` and `screen_input`. | `sksecurity-mcp` |

## Guarantees

- Every command is read-only with respect to the files it inspects. Nothing is
  moved, deleted or chmod-ed. (Version 1.x had an auto-quarantine that moved the
  scanned path; it was removed in 2.0.)
- No network calls. The optional sk-alert publish goes to the local skcapstone
  SDK, not to the network.
- The test suite sets `HOME` and `SKCAPSTONE_HOME` to tmp dirs and
  `SK_STANDALONE=1` (`tests/conftest.py`), so it cannot touch real state.

## External users

| Consumer | Uses |
|---|---|
| `skcapstone` | `sksecurity.kms` (KMS, FileKeyStore, `_hkdf_derive`, `_aes_gcm_encrypt`, `_aes_gcm_decrypt`), and `sksecurity.__version__` |
| `capauth` | `sksecurity.pqc_report` |
| CI in this and other repos | `sksecurity claims scan .` |

## What was removed

The scanner, quarantine, SQLite event store, Flask dashboard, PDF report, threat
intelligence feed, runtime monitor, Ollama client, skseed truth engine and the
YAML config. See `CHANGELOG.md`.
