# Changelog

All notable changes to `sksecurity` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
