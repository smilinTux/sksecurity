# sksecurity evaluation, 2026-11

Status: DRAFT for Chef, Phase 1 complete (read-only) and Phase 2 recommendation. Nothing here is approved. No unit, timer or install was changed. One
registry timestamp was rewritten by accident by the test suite; see 1.7.

Estate coverage and fleet evidence in sections 2 and 3 came partly from a read-only research subagent; claims marked unverified are not confirmed. Evaluated on noroc2027 by Lumina, branch `eval/sksecurity-2026-11` at `4c9f86f`.
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


**Correction to the registration story.** The skscheduler state file
(`~/.skcapstone/scheduler/noroc2027/state.json`) counts 0 successful runs and
107 errors for `sksecurity_intel_refresh`. The legacy audit unit's run ledger
holds 9 records, all exit 2, the last on 2026-08-22. Cards `a07b438f`
(review since 2026-08-23) and `307e74f4` already say "retire the CI, or
actually deploy it. Not both, not neither."

### 1.7 Side effect caused by this evaluation (disclosure)

Running the test suite once with the real `HOME` rewrote two live files at
2026-11-11 08:16 local: `~/.skcapstone/registry/sksecurity.json`
(`registered_at` moved from `2026-09-03T03:53:41Z` to `2026-11-11T13:16:38Z`)
and `~/.skcapstone/config/jobs.d/sksecurity_intel_refresh.yaml` (same
content, new mtime). Cause: `tests/test_monitor.py` calls
`SecurityMonitor.start()`, which calls `integration.register_self()` and
`ensure_schedule()` (`monitor.py:208-209`), and the test does not isolate
`HOME`/`SKCAPSTONE_HOME`. No sk-alert went out, and the CMDB CI
(`~/.skcapstone/cmdb/ci-service-sksecurity`, last written 2026-08-20) has not
picked it up yet. Nothing was reverted, because restoring the old timestamp
would be a second registry edit. That needs Chef's approval. This is the same
bug class as card `c4cdee34` (cloud9 `test_no_leak_to_real_home`) and
belongs in step 0 of the plan.

## 2. Estate needs and current coverage

| Estate need | Current coverage (evidence) | Gap | What sksecurity could do |
|---|---|---|---|
| Secrets committed to git | gitleaks in CI on 37 of 43 repo dirs (`secret-scan.yml`), GitGuardian on skharness only. Not covered: agent-seats, skcall, wt-base (no workflows), hermes-nextcloud-talk, hermes-skchat-channel, hermes-skworld, skrsi (no scanner) | 7 repos. CI only sees pushes, never the working tree or untracked files | Nothing new in CI. Its `guard install` pre-commit hook is redundant with gitleaks |
| Secrets OUTSIDE git: remotes, units, `.env`, transcripts, chat exports | **None.** All 9 `ke-leak-*` KEDB entries (`~/clawd/skbrain-ops/pages/known-errors/`) were found by hand, and none records a detector. 4 of the 9 classes sit where CI cannot see them: PATs embedded in `.git/config` remote URLs (dvre, ww301), an API key in a committed systemd unit and a chat export (nvidia), and a tracked `.env` (skgentis). Card `7defb38b`, a DSN printed into a transcript, was found by a person | **The biggest gap, and the one Chef named ("on the filesystem")** | A scheduled filesystem secret sweep: remote URLs, unit files and drop-ins, `.env` files, agent session transcripts. It reports location and class plus a value fingerprint, never the value |
| File permissions on secret material | **None.** sk-cron-run checks its own env file only (mode 600 + owner) | No sweep of `~/.config/**/*.env`, keyrings, ssh keys, `~/.skcapstone/**/secrets` | The same sweep, with a mode/owner rule set |
| Python dependency CVEs in `~/.skenv` and SK* repos | **None.** pip-audit, osv-scanner and bandit are absent everywhere, dependabot covers 2 repos, Renovate is configured but has opened zero PRs (skstacks `docs/skpatch-program.md` §7) | Total | Run `pip-audit` (or osv-scanner) against `~/.skenv` and each repo's lock/requirements |
| Host OS package CVEs | skaegis (Wazuh) approved by Chef 2026-11-11 as the Detect layer, `optional/skaegis`, target v2.26.21, placement open. skpatch-hosts is live for patching | Covered by an approved plan | **Nothing. Do not duplicate skaegis** |
| Host drift (SUID, ports, users, sshd, units, cron, authorized_keys) | Hermes job `infra-security-scan-daily` (`~/clawd/skills/infra-security-scan/scripts/infra_scan.py`), baseline diff, 07:17 daily. Its LLM triage step failed today (502 on the gateway) | Results do not reach ITIL | Optionally reuse sksecurity's ITIL reporter for it later. Do not rebuild it |
| Network intrusion / ban lists | sksec design (CrowdSec, Falco, Suricata) in skstacks `v2/docs/services/sksec.md`, "deploy-ready", not seen running | skstacks work | Nothing |
| Container image / IaC scanning | trivy + semgrep + gitleaks in skstacks `skred-scan.yml`, nightly, repo source only, output a GitHub artifact | Images not scanned, artifact read by nobody | Nothing (belongs in skbom/skpatch) |
| Mail: malicious attachments and links | **None on the client side.** `email-triage`, `ingest-email` and `email-brief` read Gmail through skos. `gtd-mail attachments --save/--telegram` downloads attachments and forwards them to Chef's Telegram DM **unscanned**. Gmail's own scanning is the only filter. Server side, skmail sets `ENABLE_CLAMAV: "1"`. | Unscanned attachments reach a chat DM and disk | Scan attachments before `gtd-mail` saves or forwards them (ClamAV + file-type rules), and check links with the existing `email_screener` heuristics, improved |
| Nextcloud uploads | skhub ships a clamav service, but `enable_files_antivirus` defaults to `false`. Whether the live nor and nam hubs have it on is not verified | Possibly none | Nothing in sksecurity. Turning on `files_antivirus` is a skstacks setting |
| Prompt injection in content fed to agents | `email_screener` prompt-injection and social-engineering rules exist but no caller uses them (skos mail does not import sksecurity) | Unused | Wire `screen` into skos mail ingest as a tag or downgrade signal |
| Reporting to ITIL/KEDB | Auto-incident producers exist (`skcapstone/service_health.py:788` with dedup via `find_open_incident_for_service`, `syncthing_guard.py`, `skcoord/cmdb_scheduler.py`). KEDB entries come from the problem flow (`create_kedb=True`, `skcoord/itil.py:1637`). sksecurity reports to nobody | No security producer | One reporter: finding fingerprint, then dedup against open incidents, then incident with tag `ke-leak-<class>` when the class matches a KEDB entry, else a problem |
| PQC posture, honest-claims gate, KMS | sksecurity `pqc-*`, `claims`, `kms`. These are real, used (capauth, skcapstone, CI) and working | None | Keep |

## 3. Fleet fit

- **Declaration:** `skcapstone/deploy/fleet-objects/profile/control.json:93`
  requires `sksecurity-audit.timer`. `docs/fleet/control-unit-set.md:118`
  lists it as absent ("safe, duplicates reports"). The `builder-standby`
  profile (.41) requires the package. `sksecurity` is not in
  `deploy/fleet-constraints.txt`. KE `ke-dcd70aa5` says to run it from
  `~/.venvs/sksecurity`, which does not exist. It lives editable in the
  shared `.skenv`.
- **Registry:** `~/.skcapstone/registry/sksecurity.json`, `health_url: null`,
  `pid_file: null`. It carries no health signal at all, so the CMDB can only
  ever say "registered, nothing running".
- **Three schedulers, of which it uses the two wrong ones.** The systemd
  timer (dead script) and the skcapstone skscheduler (`jobs.d`, failing
  daily). The estate norm for batch jobs is the **skos scheduler**
  (`~/clawd/skos/deploy/schedule/jobs.yaml`, rendered to crontab by
  `skos schedule install`). It runs 24 jobs through `sk-cron-run`, which
  already gives a ledger (`~/.skcapstone/logs/cron-ledger.jsonl`), a GTD
  capture on failure, and one streak-deduped sk-alert.
- **Nodes (nor):** control `.158` (noroc2027) holds the mail jobs, gog and
  most of the checkouts. builder-standby `.41` holds checkouts and agent
  sessions. worker-gpu `.100` has fewer user secrets but its own `.skenv`.
  The observer norpv1300 is never installed into. chi is Casey's estate and
  shares code only, so the package is available to it, not imposed.

## 4. Recommendation: refactor and narrow, then extend

**Not retire:** skcapstone (`kms.py`, `pillars/security.py`,
`mcp_tools/security_tools.py`) and capauth (`pqc_report`) import it, the
honest-claims gate runs in CI, and the estate has a real, unowned gap that
matches Chef's intent exactly: secrets and permissions on the filesystem,
Python dependency CVEs, and mail attachments. **Not keep as is:** its
headline feature is broken, would be destructive if fixed naively, and its
only live footprint is a daily false alarm. **Not a full rewrite:** about
40 percent of the code (guard, claims, pqc, kms, email_screener) is real
and tested. The right move is to delete the fake SOC shell, keep the real
parts, and add a small sweep-and-report core that **wraps proven scanners**
(gitleaks, pip-audit, ClamAV) instead of growing its own regexes.

### Step 0, safety, BEFORE any crash is fixed (0.5 day)

The constructor crash is the only thing standing between `sksecurity scan`
and `shutil.move` of the whole scanned directory. So, in this order and in
one PR:

1. Remove auto-quarantine. `scan` (and anything that replaces it) is
   report-only and never moves, deletes or chmods a file. Delete
   `QuarantineManager.quarantine`'s move path, or the whole module (step 1).
   Add a test that runs `scan` over a tmp tree above threshold and asserts
   every file is still in place.
2. Fix test isolation: an autouse `conftest.py` fixture that points `HOME`
   and `SKCAPSTONE_HOME` at `tmp_path` and sets `SK_STANDALONE=1`, plus a
   test that fails if anything under the real `~/.skcapstone` changes.
3. Stop `SecurityMonitor.start()` from self-registering and from writing
   the scheduler drop-in (delete `ensure_schedule`, `register_self` calls).
4. Only then fix or delete the broken `config=` call paths.

### Step 1, delete the fake SOC shell (1 day)

Delete `scanner.py` (regex code-smell linter; semgrep is already in
`.skenv`, bandit does it properly), `quarantine.py`, `database.py`,
`dashboard.py`, `pdf_report.py`, `intelligence.py` and `community-threats/`
(a feed that never loaded), `truth_engine.py`, `ai_client.py`, `monitor.py`,
`config.py` as it stands, and the CLI commands `scan`, `audit`,
`quarantine`, `status`, `update`, `monitor`, `dashboard`, `init`. Keep
`guard`, `claims`, `screen`, `pqc-*`, `kms` and the integration `alert()`.
Trim the MCP server to working tools and fix `screen_input` to call the email
screener. Bump to 2.0.0 (breaking CLI).

### Step 2, filesystem secret and permission sweep (2 to 3 days)

`sksecurity sweep fs`, report-only:

- gitleaks (pinned skfleet binary, `dir` mode, no git history) over
  `~/clawd`, `~/.config`, `~/.skcapstone`, `~/.hermes`, `~/skworld-worktrees`
  and the agent `sessions/` and Claude/T3 transcripts, with excludes for the
  sanctioned stores (skvault db, gog keyring dir, `0600` env files that are
  the intended home of a secret).
- Rules sized to the 9 KEDB classes: credentials in `.git/config` remote URLs
  across every checkout, `Environment=` secrets in systemd units and
  drop-ins, tracked `.env` files (`git ls-files` per repo), DSNs with
  passwords in transcripts and shell history (card `7defb38b` class).
- Permission rules: secret-bearing files (`*.env`, keyrings, ssh private
  keys, `*/secrets*`) must be `0600`/owner-only, their directories not
  group or world writable.
- Output is a finding with path, line, class, rule, and a salted SHA-256
  fingerprint of the value. **The value itself is never stored, logged or
  sent**, matching the `ke-leak` pages.

### Step 3, ITIL reporter (1 to 2 days, can run alongside step 2)

One `report` module used by every sweep, copying the
`service_health.py` pattern: deterministic id from the fingerprint, then
`find_open_incident` dedup, then create. A finding whose class matches a
`ke-leak-*` KEDB entry opens an incident tagged with that KE (sev2 for a
live credential, sev3 for a permission issue). A new class opens a problem
so the KEDB entry comes out of the existing problem flow. A resolved
fingerprint (gone on the next sweep) adds an event, never auto-closes.
Also one sk-alert per run summary, not per finding.

### Step 4, dependency audit (1 day)

`sksecurity sweep deps`: `pip-audit` against `~/.skenv` (and other fleet
venvs found by the runtime discovery from PR #11) and each SK* repo's
requirements/lock. Reports through step 3, one incident per
package+advisory, sev2 for critical/high with a fix available. OS packages
are skaegis's job, not this.

### Step 5, mail attachments and links (2 days)

`sksecurity sweep mail` hooks into the existing pipeline rather than a
second mail reader: `gtd-mail attachments` calls `sksecurity screen-file`
before it saves or forwards to Telegram (ClamAV `clamscan` if installed,
plus the file-type and double-extension rules already in
`email_screener._check_attachments`, plus macro detection for Office files).
A positive blocks the forward and opens an incident. Links: improve the
screener (shorteners, subject line, lookalike domains, punycode) and tag
skos mail items rather than block them. Read-only against Gmail through
`gog`; never modify a mailbox. Nextcloud `files_antivirus` is a separate
skstacks change, listed for Chef, not built here.

### How it runs

- **skos scheduler + sk-cron-run**, the estate norm: `sweep fs` daily,
  `sweep deps` daily, `sweep mail` inline in the mail job (no schedule of
  its own).
- **Nodes:** `fs` and `deps` on control `.158` and builder `.41` (both hold
  checkouts and sessions), `deps` on worker `.100`. `mail` on `.158` only,
  where the gog mail jobs run. Not on the observer. chi may opt in.
- **Retire (needs Chef's approval, each a fleet change):** the
  `sksecurity-audit.service/.timer` units and their drop-in, the
  `jobs.d/sksecurity_intel_refresh.yaml` drop-in (ends the daily false
  alert), the `control.json:93` requirement on the timer, KE `ke-dcd70aa5`'s
  stale venv advice. Replace the registry entry with one whose health is the
  last sweep's ledger record, so the CMDB can tell "ran clean" from
  "not running". Close cards `a07b438f` and `307e74f4` against this plan.

### Effort

About 8 to 10 agent-days: step 0 0.5, step 1 1, step 2 2 to 3, step 3 1 to 2,
step 4 1, step 5 2, plus repo cleanup 0.5. Steps 0 and 1 are one PR and
should land first. Steps 2 and 3 are the value Chef asked for.

Later, not in this plan: move `kms.py` into its own package or capauth
(it is a dependency of skcapstone that has nothing to do with scanning), and
let `infra-security-scan` report through the same ITIL reporter.

## 5. Repo cleanup list

Goal: a repo that is source, tests and docs a new user can install from.

**Delete**

- Hype and status docs: `REVOLUTIONARY_BREAKTHROUGH.md`,
  `WHY_SKSECURITY_IS_PIONEERING.md`, `AI_REMEDIATION_EXPLAINED.md`,
  `CONVERSATIONAL_BUG_FIXED.md`, `DNS_STATUS.md`, `INSTALLATION_STATUS.md`,
  `MISSION.md` (fold one honest sentence into the README), `marketing/`.
- Demo and fixture debris at the root: `demo_vulnerable.py`,
  `demo_vulnerable.py.backup.20260216_024836`, `test_vulnerable_code.py`,
  `test_vulnerable_code.py.backup.20260216_024723` (move a minimal fixture
  under `tests/fixtures/` if a test needs one).
- Orphan root Python not in the package: `ai_remediation_engine.py` (card
  `f0b6612c`: "just adds TODO comments"), `conversational_handler.py`
  (OpenClaw handler).
- OpenClaw (evicted 2026-04-23): `openclaw-plugin/`, `skill.yaml`, the
  `init --framework openclaw` option.
- JS bridge (npm publishing already dropped in `92e4aff`): `package.json`,
  `index.js`, `index.d.ts`, `bin/cli.js`.
- Static pages: `dashboard.html`, `index.html`, `assets/dashboard.html`
  (keep `assets/security-logo.svg` if the README uses it).
- `INTEGRITY_MANIFEST.json` (hashes files from 1.2.1 incl. a `setup.py`
  that no longer exists), `requirements.txt` (duplicates pyproject).
- Legacy `scripts/`: `advanced_security_system.py`,
  `conversational_security.py`, `daily_security_audit.py`,
  `install_security.py` (generated the dead units), `scan_skill.py`,
  `security_dashboard.py`, `update_threats.py`, `generate-manifest.sh`.
  Review `install-runtime.sh` (PR #10) and keep only if a step still uses it.
- `install.sh` (12 KB curl-to-shell installer for the old product) once the
  README shows `pip install sksecurity`.
- `docker/`, `docker-compose.yml`, `.env.example`, `scripts/build-docker.sh`,
  `scripts/push-docker.sh` (a container for the dashboard that is being
  deleted; nothing in the fleet runs it).
- `references/threat_patterns.json`, `references/security_config.yml`
  (configs for the deleted engine), `docs/SKSENTRY.md` (unbuilt design;
  move to an `ideas/` note in skcapstone if wanted).

**Keep, and rewrite where noted**

- `sksecurity/` (after steps 0 and 1), `tests/`, `pyproject.toml` (drop
  `sqlalchemy`, `watchdog`, `psutil`, `email-validator` and the `web`/`pdf`
  extras once their users are deleted), `LICENSE`, `CHANGELOG.md`,
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `.github/`,
  `.gitleaks-baseline.json`, `.honestclaims-allow`.
- `README.md`: rewrite to what ships (sweeps, guard, claims, pqc, kms) with
  real example output; remove every "enterprise" claim.
- `SOP.md`, `SKILL.md`: rewrite after the refactor (run, read, triage).
- `docs/`: keep `honest-claims.md`, `pqc-posture.md`, `pqc-progression.*`,
  `QUANTUM_RESISTANCE.md`, `INFERENCE-GATEWAY.md`, `audit-2026-06-28.md`;
  rewrite `ARCHITECTURE.md`; this file.

## 6. Decisions for Chef

1. Approve the direction (refactor and narrow, then extend) and the step order,
   with step 0 first.
2. Approve retiring the dead units, the `sksecurity_intel_refresh` drop-in
   and the `control.json` timer requirement (these end the daily false
   alert).
3. Approve restoring `registered_at` in `~/.skcapstone/registry/sksecurity.json`
   to `2026-09-03T03:53:41Z`, or leave it until the registry entry is
   replaced in the plan.
4. Approve installing pinned `gitleaks`, `pip-audit` and `clamav` on the
   sweep nodes.
5. Separately, for skstacks: whether to turn on Nextcloud `files_antivirus`
   on the nor and nam hubs.
