# sksecurity evaluation, 2026-11

Status: DRAFT, Phase 1 (read-only). Nothing here is approved. No unit, timer,
registry or install was changed to produce it.

Evaluated on noroc2027 by Lumina, branch `eval/sksecurity-2026-11` at `4c9f86f`.
Installed copy: `~/.skenv`, `sksecurity 1.2.8.dev1+g4c9f86f53`, an editable
install pointing at the main checkout `~/clawd/skcapstone-repos/sksecurity`
(same commit as this branch).

## 1. What the code really does

All runs below used throwaway targets in the session scratchpad and, where the
command writes state, a fake `HOME`.

### 1.1 CLI commands

| Command | Claims | Reality today | Evidence |
|---|---|---|---|
| `scan PATH` | multi-layer AI agent vuln scan | **CRASHES** on every call | `SecurityDatabase.__init__() got an unexpected keyword argument 'config'`, exit 1 |
| `audit` | comprehensive audit + PDF | **CRASHES** | `QuarantineManager.__init__() got an unexpected keyword argument 'config'` |
| `quarantine` | manage quarantined threats | **CRASHES** | same as audit |
| `status` | system health | **CRASHES** after printing the pattern count | same `SecurityDatabase` error |
| `update` | pull threat intel from Moltbook, NVD, GHSA, community | **CRASHES** | `ThreatIntelligence.update() got an unexpected keyword argument 'sources'` |
| `monitor PATH` | runtime agent monitoring | not exercised; a psutil process/CPU poller, not a security monitor | `monitor.py` 236 lines |
| `dashboard` | SOC dashboard | Flask app on localhost:8888, reads the same broken DB/quarantine classes; needs the `[web]` extra | `dashboard.py` |
| `init --framework openclaw/autogpt/langchain` | framework bootstrap | writes a config file; OpenClaw was evicted 2026-04-23 | `cli.py:233` |
| `guard scan/staged/install/text` | secret leak prevention | **WORKS.** 12 regex patterns, redacts matches, skips `.git`/venvs | found a planted AWS key, a hardcoded password and a Mongo DSN in a 3-file target |
| `screen` | email / input screening | **WORKS, shallow.** Text-only regex heuristics | textbook phish (`.tk` + "login" host + "account suspended") scored 71 MALICIOUS; `click http://bit.ly/x to verify your password now` with subject `Urgent` scored **0 SAFE**; a plausible credential-harvest note scored 0 |
| `claims scan/text` | honest-claims gate | **WORKS**, used for real | `docs/audit-2026-06-28.md`, CI workflow `honest-claims.yml` |
| `pqc-report/posture/dashboard/snapshot` | PQC self-report | **WORKS**, real live data | live posture: 6 surfaces, "729/1147 groups hybrid"; imported by `capauth/cli.py:1842` |
| `pqc-stacks` | per-service PQC itemization | fails here: expects SKStacks at `~/clawd/SKStacks` or `SKSTACKS_ROOT` | `no SKStacks v2 descriptors found` |

Why 362 tests pass while five headline commands crash: `tests/test_cli.py` only
checks `--help` and `--version`. The module tests construct classes with no
`config`, which is the one path the CLI never takes.

### 1.2 The `scan` engine, if it did run

`SecurityScanner` is a grep for 12 built-in regexes (`eval(`, `subprocess.*(`,
`os.system(`, `pickle.load`, `yaml.load`, `curl | sh`, AWS/GitHub/npm tokens,
PEM headers) plus three heuristics (long lines, Shannon entropy over 7.5,
"more than 10 risky imports"). Called directly from Python (bypassing the CLI
crash):

- `sksecurity/` itself: 22 files, 1 finding, risk 56.8.
- `skmemory/skmemory/`: 171 files, 39 findings (19 `subprocess`, 17 `eval/exec`), **risk 100.0**.

It is a code-smell linter, not a vulnerability scanner: no CVE data, no
dependency resolution, no taint analysis. Bandit and semgrep do this job
properly.

**Hazard:** `scan` defaults to `--quarantine` with threshold 80, and the
quarantine step `shutil.move`s **the whole scanned path** into the quarantine
dir (`cli.py:89`, `quarantine.py:110`). The constructor crash is currently the
only thing stopping `sksecurity scan ~/clawd/skcapstone-repos/skmemory` from
moving the skmemory source tree. Any fix that makes `scan` run must remove
auto-quarantine first.

### 1.3 Threat intelligence feed

- Default sources are the repo's own `community-threats/patterns/*.json` on
  raw.githubusercontent.com. This is the only outbound call besides the opt-in
  Ollama client at `localhost:11434`. No telemetry, nothing else phones home.
- The feed can never load even when `update` is fixed: the files are
  `{"patterns": [...]}` with a `pattern` key, while the parser iterates the
  top level and reads `value`. So the bundled 2026-03 feed has never reached
  the scanner. Only the 12 hardcoded patterns are ever used.
- Indicators live in memory only; nothing persists a fetched feed.
- "Moltbook, NVD, GitHub Security Advisories" in the `update` help text do
  not exist in code. `docs/SKSENTRY.md` (crowdsourced feed) is a design doc,
  not implemented.

### 1.4 MCP server (`sksecurity-mcp`)

Five tools: `scan_path` (the regex scanner, without the DB, so it runs),
`screen_input` (mislabelled: it calls the **secret guard**, not the email
screener), `check_secrets` (secret guard), `get_events` (empty DB),
`monitor_status` (psutil CPU/RAM numbers). Registered in
`~/.hermes/config.yaml`; not in Claude Code's config.

### 1.5 Other modules

- `kms.py` (836 lines): a real HKDF + AES-GCM key-wrapping KMS. **Load-bearing:**
  `skcapstone/kms.py` imports it, and skcapstone's `security_status` /
  `security_audit_log` MCP tools and `pillars/security.py` import `sksecurity`.
  It has nothing to do with scanning and is misplaced in this package.
- `pqc_report.py`, `pqc_posture.py`, `pqc_stacks.py` (2,100 lines): real and
  used (capauth imports `pqc_report`). Also not scanning.
- `honest_claims.py`: real, used in CI.
- `secret_guard.py`, `email_screener.py`: real but shallow (see 1.1).
- `integration.py`: publishes `sksecurity.<level>` on sk-alert and registers a
  scheduler job. Only `monitor.py` calls `alert()`.
- `truth_engine.py`: optional skseed "Steel Man Collider" wrapper; no caller
  outside tests.
- `ai_client.py`: optional Ollama explainer; defaults to `llama3.2`, not the
  fleet's skgateway.
- `database.py`, `quarantine.py`, `config.py`, `dashboard.py`, `pdf_report.py`:
  the broken SOC shell around `scan`.

### 1.6 What actually runs on noroc2027 today

The CMDB drift ("registered, nothing running") is half right.

1. **`sksecurity-audit.timer`** (disabled) and its service in
   `~/.config/systemd/user/` with an `sk-cron-run` drop-in. Its `ExecStart` is
   `/usr/bin/python3 /home/cbrd21/clawd/security/scripts/security_cron.py`,
   **a file that no longer exists** (`~/clawd/security/` now holds only
   `dashboards/`, `logs/`, `reports/`). That script ran the legacy
   `advanced_security_system.py full-audit`, which is a copy of this repo's
   `scripts/`, not the package. It wrote 157 daily reports,
   2026-03-11 to 2026-08-18, into `~/clawd/security/reports/<date>/`: a
   skill-folder scan of `~/clawd/skills` (91 skills, "3 CRITICAL" standing for
   months). Nobody read them; nothing went to ITIL.
2. **skscheduler job `sksecurity_intel_refresh`**, from
   `~/.skcapstone/config/jobs.d/sksecurity_intel_refresh.yaml`, written by
   `integration.ensure_schedule()`. It runs `sksecurity update --sources all`
   every 24 h and **fails every day**: 96 `❌ FAILED` warn alerts in
   `~/.skcapstone/agents/lumina/logs/skalert.log` since 2026-07-17 (first
   `No such file or directory: 'sksecurity'`, then the `update()` TypeError,
   last seen 2026-11-10 in the user journal). Zero `sksecurity.*` detection
   alerts have ever been published.

So the only live footprint of sksecurity is a daily false-failure alert.

## 2. Estate needs and current coverage

PENDING (estate map in progress).

## 3. Fleet fit

PENDING.

## 4. Recommendation

PENDING.

## 5. Repo cleanup list

PENDING.
