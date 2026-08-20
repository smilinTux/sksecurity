# Changelog

All notable changes to `sksecurity` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Operations

- Add `scripts/install-runtime.sh` and SOP ownership rules for the isolated
  `~/.venvs/sksecurity` operational runtime. The shared SK Python environment is
  no longer an installation target for the CLI, MCP server, or optional extras.
- Make the runtime installer discover an existing fleet-managed Python when an
  unversioned host default is newer than the node's supported runtime.

### Fixed (docs)

- **`SOP.md` section 5 gave a FALSE reason for "no network surface."** It claimed the
  `dashboard_port` knob was "an unimplemented placeholder, no HTTP server backs it."
  `sksecurity/dashboard.py` is in fact a Flask application with 16 routes (including
  unauthenticated `/api/kms/rotate`, `/api/scan` and `/api/quarantine/restore`) that
  calls `app.run()`, and `scripts/security_dashboard.py` binds a second standalone
  `HTTPServer` on `localhost:8888`. The conclusion (nothing listens) survives, but only
  because the `sksecurity dashboard` CLI command is broken, which section 8 now
  documents as an open defect with a reproducer.
- **`SOP.md` section 9 quoted `SemVer: 1.2.1`,** four tags stale and contradicting
  `pyproject.toml`, which sets `dynamic = ["version"]` and derives the version from the
  git tag via setuptools-scm. The SOP now says where the version comes from instead of
  quoting one.
- **`SOP.md` section 5 now records that `sksecurity-audit.service`/`.timer` executes
  `~/clawd/security/scripts/security_cron.py`,** which lives outside this repo and
  imports nothing from `sksecurity`. That timer being green verifies no code here.
- **`SOP.md` section 7 CLI list** was missing the `claims` and `pqc-*` command families,
  which are the repo's enforcement and evidence surfaces.

### Added

- **Executable docs evidence**: a `docs-evidence` block at the end of `SOP.md` with 9
  hermetic checks pinning the entry points, the setuptools-scm version policy, the
  dashboard Flask/port facts, the KMS and data-root paths, the honest-claims CI gate,
  and the open dashboard-CLI defect. Every check was negative-tested. Wired to CI via
  `.github/workflows/docs-check.yml` (tiers 1,2 for now; tier 3 once it has run clean).

- **sk-standards doc set** — `SOP.md` (9 sections + mermaid architecture & PQC
  self-report diagrams), `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, this
  `CHANGELOG.md`; README cross-link block + stated maturity tier +
  CRYPTOGRAPHY_STANDARD compliance line. Per the sk-standards `SK_REPO_DOC_STANDARD`
  (coord `237f38a1`).

### PQC (recent, pre-changelog history)

- **Self-report learns the DM ratchet level** (RFC-0001 P4) — per-channel
  hybrid-vs-classical reporting extended.
- **PQC ledger** — entries documenting the Sequoia PQC signing backend availability
  and the PQC root proven end-to-end through capauth. SKSecurity is the ecosystem's
  evidence engine for these claims. Epic `PQC-MIGRATION` (coord `e1d6ba2a`).

## [1.2.1]

Current published line.

### Added

- **Threat scanner** — multi-layer file/dir scan → weighted `risk_score` (0–100),
  `ThreatMatch` list, recommendations.
- **Secret guard** — 14 secret patterns (AWS, GitHub, npm, OpenAI, Slack, SendGrid,
  Square, Stripe, Mongo/Postgres URLs, generic `key=…`, JWT, private keys) + git
  pre-commit hook + test-context FP reduction.
- **Email/input screener** — 7 `ThreatCategory` verdicts (phishing, prompt injection,
  credential leak, malicious link, social engineering, malware payload, data
  exfiltration) before a model sees content.
- **Sovereign KMS** — hierarchical keys (Master→Team→Agent→DEK), AES-256-GCM wrap,
  scrypt master seal, HKDF-SHA256 derivation, rotation, immutable audit log.
  Symmetric/hash → quantum-acceptable.
- **Quarantine** (SHA256 integrity records), **runtime monitor** (psutil), **truth
  engine** (Steel Man Collider verification), **audit DB** (SQLite), **web
  dashboard**, **PDF audit report**.
- **MCP server** — `scan_path · screen_input · check_secrets · get_events ·
  monitor_status`.
- **Integration adapter** — optional skcapstone bridge (sk-alert bus +
  skscheduler intel-refresh job), default-on by package presence.
- **Local-first** — all findings stored under `~/.sksecurity/`, never phones home.

### Security

- Honest-claim posture: SKSecurity's own crypto (KMS) is **symmetric/hash, already
  quantum-acceptable**; it holds no asymmetric key material. AES-256 is **not**
  described as quantum-broken.

[Unreleased]: https://github.com/smilinTux/sksecurity/compare/v1.2.1...HEAD
[1.2.1]: https://github.com/smilinTux/sksecurity/releases/tag/v1.2.1
