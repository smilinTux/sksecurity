# SKSecurity Architecture

Comprehensive security architecture for sovereign AI agent ecosystems.
This document covers every major component, the data flows between them,
and the operational cycles that keep the system running autonomously.

---

## 1. System Overview

```mermaid
flowchart TB
    subgraph ENTRY["Entry Points"]
        CLI["sksecurity CLI"]
        MCP["MCP Server\n(stdio transport)"]
        DASH["Web Dashboard\n(Flask REST)"]
        API["Python API"]
        CRON["systemd Timer\n(daily audit)"]
    end

    subgraph CORE["Core Security Engine"]
        SCAN["SecurityScanner\n(scanner.py)"]
        GUARD["SecretGuard\n(secret_guard.py)"]
        INTEL["ThreatIntelligence\n(intelligence.py)"]
        KMS["Sovereign KMS\n(kms.py)"]
        QUAR["QuarantineManager\n(quarantine.py)"]
        SCREEN["EmailScreener\n(email_screener.py)"]
        MON["RuntimeMonitor\n(monitor.py)"]
        TRUTH["TruthEngine\n(truth_engine.py)"]
    end

    subgraph DATA["Data Stores"]
        DB[("SecurityDatabase\nSQLite3")]
        QDIR[("~/clawd/quarantine/\nQuarantined Files")]
        KSTORE[("~/.sksecurity/kms/\nKey Store")]
        TCACHE[("threat_cache.json\nLocal IOC Cache")]
    end

    subgraph OUTPUTS["Outputs"]
        PDF["PDF Report\n(Enterprise)"]
        JSON_OUT["JSON Report\n(Pro)"]
        TXT["Text Report\n(Community)"]
        TG["Telegram Alert"]
    end

    subgraph EXTERNAL["External Threat Sources"]
        MOLT["Moltbook\nsmilintux.org"]
        NVD["NVD\nnist.gov"]
        GHSA["GitHub Security\nAdvisories"]
    end

    CLI --> SCAN & GUARD & QUAR & KMS
    MCP --> SCAN & GUARD & SCREEN & MON
    DASH --> SCAN & QUAR & MON & INTEL
    API --> CORE
    CRON --> SCAN & INTEL

    EXTERNAL --> INTEL
    INTEL --> TCACHE
    INTEL --> SCAN
    SCAN --> DB
    SCAN -->|"risk >= 80"| QUAR
    QUAR --> QDIR
    GUARD --> DB
    SCREEN --> DB
    MON --> DB
    KMS --> KSTORE
    KMS -->|"audit entries"| DB
    TRUTH -->|"verify"| SCAN & SCREEN

    DB --> PDF & JSON_OUT & TXT
    DB --> TG

    AI["AI Client\n(Ollama / OpenAI)"]
    SCAN --> AI
    SCREEN --> AI
    GUARD --> AI

    CONFIG["SecurityConfig\n(sksecurity.yml)"]
    CONFIG --> CORE
```

---

## 2. Audit Pipeline

The daily audit cycle runs unattended via a systemd timer. It updates
threat intelligence, scans every skill in `~/clawd/skills/`, generates
reports at three tiers, and pushes critical findings to Telegram.

```mermaid
sequenceDiagram
    participant Timer as systemd Timer
    participant Cron as daily_security_audit.py
    participant ASS as advanced_security_system.py
    participant Intel as ThreatIntelligence
    participant Scanner as SecurityScanner
    participant DB as SQLite DB
    participant QM as QuarantineManager
    participant Report as Report Generator
    participant TG as Telegram

    Timer->>Cron: OnCalendar trigger (daily)
    activate Cron

    Note over Cron: Phase 1 - Threat Intel Update
    Cron->>ASS: enhanced_threat_intelligence()
    ASS->>Intel: fetch from Moltbook
    Intel-->>ASS: threat patterns
    ASS->>Intel: fetch from NVD
    Intel-->>ASS: CVE data
    ASS->>Intel: fetch from GitHub Advisories
    Intel-->>ASS: advisory data
    ASS->>DB: store threat_intelligence rows
    ASS-->>Cron: intel updated

    Note over Cron: Phase 2 - Skill Scanning
    Cron->>Cron: enumerate ~/clawd/skills/*
    loop For each skill directory
        Cron->>Scanner: scan_skill(skill_path)
        Scanner->>Scanner: static pattern matching
        Scanner->>Scanner: behavioral heuristics
        Scanner->>Scanner: dependency check
        Scanner->>Scanner: AI analysis (optional)
        Scanner->>DB: log security_events
        Scanner-->>Cron: ScanResult (risk_score 0-100)
        alt risk_score >= 80
            Cron->>QM: quarantine(skill_path)
            QM->>QM: check whitelist.json
            alt skill in whitelist
                QM-->>Cron: SKIP (whitelisted)
            else skill not whitelisted
                QM->>QM: shutil.move -> ~/clawd/quarantine/
                QM->>QM: compute SHA256 hash
                QM->>QM: write records.json
                QM-->>Cron: QuarantineRecord
            end
        end
    end

    Note over Cron: Phase 3 - System Checks
    Cron->>Cron: verify scanner present
    Cron->>Cron: verify threat cache fresh
    Cron->>Cron: check disk/permissions

    Note over Cron: Phase 4 - Report Generation
    Cron->>Report: generate Community report (text)
    Cron->>Report: generate Pro report (JSON)
    Cron->>Report: generate Enterprise report (PDF)
    Report->>DB: query events, quarantine, metrics
    Report-->>Cron: reports written

    Note over Cron: Phase 5 - Notification
    alt critical findings exist
        Cron->>TG: send alert summary
        TG-->>Cron: delivered
    end

    deactivate Cron
```

---

## 3. Threat Intelligence Flow

Threat data flows from three external sources through a normalization
layer into a local SQLite database. The scanner consults this DB on
every scan, and the system falls back to a cached JSON file when
upstream sources are unreachable.

```mermaid
flowchart LR
    subgraph SOURCES["External Sources"]
        MOLT["Moltbook\nsecurity-feed.json"]
        NVD["NVD API v2.0\nCVE Database"]
        GHSA["GitHub\nSecurity Advisories"]
    end

    subgraph INGEST["Ingestion Layer"]
        FETCH["HTTP Fetch\n(urllib / requests)"]
        NORM["Normalize\nto ThreatIndicator"]
        DEDUP["Deduplicate\nby type+value"]
    end

    subgraph STORAGE["Storage Layer"]
        DB[("threat_intelligence\ntable in SQLite")]
        CACHE["threat_cache.json\n(offline fallback)"]
    end

    subgraph CONSUME["Consumers"]
        SCAN["SecurityScanner"]
        SCREEN["EmailScreener"]
        REPORT["Audit Reports"]
    end

    MOLT -->|"JSON feed"| FETCH
    NVD -->|"REST API"| FETCH
    GHSA -->|"REST API"| FETCH

    FETCH --> NORM
    NORM --> DEDUP
    DEDUP --> DB
    DEDUP --> CACHE

    DB --> SCAN
    DB --> SCREEN
    DB --> REPORT

    CACHE -.->|"fallback\nwhen offline"| SCAN

    subgraph PATTERNS["Built-in Pattern Library"]
        P1["code_injection\n(eval, exec)"]
        P2["command_injection\n(os.system, shell=True)"]
        P3["secrets\n(hardcoded keys)"]
        P4["deserialization\n(pickle, yaml.load)"]
        P5["sql_injection\n(execute + %)"]
        P6["path_traversal\n(../)"]
    end

    PATTERNS --> SCAN
```

### Threat Source Details

| Source | URL | Data Format | Update Frequency | Priority |
|--------|-----|-------------|------------------|----------|
| Community AI Safety | `raw.githubusercontent.com/smilinTux/SKSecurity/main/community-threats/patterns/ai-safety.json` | JSON threat patterns | Per release | 1 (highest) |
| NVD | `services.nvd.nist.gov/rest/json/cves/2.0` | JSON CVE records | Daily | 2 |
| GitHub Advisories | `api.github.com/advisories` | JSON advisories | Daily | 3 |
| Built-in Patterns | Embedded in `scan_skill.py` | Regex patterns | Per release | Always available |

---

## 4. Quarantine Decision Tree

When a scan completes, the risk score determines what happens next.
The whitelist (`whitelist.json`) provides an operator-controlled
override for skills that have been reviewed and explicitly approved.

```mermaid
flowchart TD
    START["Scan Completes"] --> SCORE{"Risk Score?"}

    SCORE -->|"0 - 29\nLOW"| PASS_LOW["PASS\nLog only"]
    SCORE -->|"30 - 59\nMEDIUM"| WARN["WARN\nLog + recommendations"]
    SCORE -->|"60 - 79\nHIGH"| WARN_HIGH["WARN HIGH\nLog + flag for review"]
    SCORE -->|"80 - 100\nCRITICAL"| CHECK_WL{"In whitelist.json?"}

    CHECK_WL -->|"Yes"| WL_PASS["PASS\nLog as whitelisted\nSkip quarantine"]
    CHECK_WL -->|"No"| CHECK_AQ{"auto_quarantine\nenabled?"}

    CHECK_AQ -->|"Yes"| QUARANTINE["AUTO-QUARANTINE"]
    CHECK_AQ -->|"No"| FLAG["FLAG\nLog + alert operator"]

    QUARANTINE --> MOVE["shutil.move\nskill -> ~/clawd/quarantine/"]
    MOVE --> HASH["Compute SHA256\nof quarantined files"]
    HASH --> RECORD["Write QuarantineRecord\nto records.json"]
    RECORD --> NOTIFY["Send Telegram alert\nwith skill name + risk score"]

    WL_PASS --> LOG_WL["Log: skill_name whitelisted\nreason from whitelist.json"]

    style QUARANTINE fill:#d32f2f,color:#fff
    style PASS_LOW fill:#388e3c,color:#fff
    style WL_PASS fill:#1976d2,color:#fff
    style WARN fill:#f9a825
    style WARN_HIGH fill:#ef6c00,color:#fff
```

### Risk Score Calculation

The scanner computes a composite risk score (0-100) from four analysis layers:

| Layer | Weight | What It Checks |
|-------|--------|----------------|
| **Static Pattern Matching** | 40% | Regex against threat DB patterns (eval, exec, shell=True, etc.) |
| **Behavioral Heuristics** | 25% | SSL verification disabled, path traversal in writes, dynamic code execution |
| **Dependency Analysis** | 20% | Known-vulnerable packages, suspicious imports, typosquatting |
| **AI-Powered Analysis** | 15% | Ollama/OpenAI contextual analysis (graceful degradation if unavailable) |

---

## 5. Integrity Verification

The Call Home / Integrity Verification subsystem ensures that deployed
skills and agent code have not been tampered with. It works by generating
SHA256 manifests, optionally GPG-signing them, and comparing against
published release manifests.

```mermaid
flowchart TB
    subgraph BUILD["Build / Release Phase"]
        SRC["Source Code\n(tagged release)"]
        GEN["Generate Manifest\nSHA256 per file"]
        SIGN["GPG Sign\nmanifest.json.sig"]
        PUB["Publish to\nrelease server"]
    end

    subgraph DEPLOY["Deployment Phase"]
        INST["Install skill\nor agent code"]
        LOCAL["Generate Local\nManifest"]
    end

    subgraph VERIFY["Verification Cycle"]
        FETCH["Fetch Published\nManifest"]
        COMPARE{"Compare\nlocal vs published\nSHA256 hashes"}
        GPGV["Verify GPG\nSignature"]
    end

    subgraph RESULT["Outcome"]
        MATCH["PASS\nIntegrity confirmed"]
        MISMATCH["FAIL\nTampering detected"]
        SIGFAIL["FAIL\nSignature invalid"]
    end

    SRC --> GEN
    GEN --> SIGN
    SIGN --> PUB

    INST --> LOCAL

    LOCAL --> COMPARE
    PUB --> FETCH
    FETCH --> GPGV
    GPGV -->|"valid"| COMPARE
    GPGV -->|"invalid"| SIGFAIL

    COMPARE -->|"all match"| MATCH
    COMPARE -->|"hash mismatch"| MISMATCH

    MISMATCH --> ALERT["Alert operator\n+ log to DB\n+ optional quarantine"]

    style MATCH fill:#388e3c,color:#fff
    style MISMATCH fill:#d32f2f,color:#fff
    style SIGFAIL fill:#d32f2f,color:#fff
```

### Manifest Format

```json
{
  "version": "1.0.0",
  "generated_at": "2026-03-11T00:00:00Z",
  "algorithm": "SHA256",
  "files": {
    "sksecurity/scanner.py": "a1b2c3d4...",
    "sksecurity/kms.py": "e5f6a7b8...",
    "sksecurity/quarantine.py": "c9d0e1f2..."
  },
  "signature": "manifest.json.sig"
}
```

> **Status:** The integrity verification system is currently under active
> development. Manifest generation and local comparison are functional.
> GPG signing integration and the published release manifest server are
> being built.

---

## 6. Report Tier Comparison

SKSecurity generates audit reports at three tiers, each targeting a
different audience and integration point.

```mermaid
flowchart LR
    DB[("SecurityDatabase\nSQLite3")] --> GEN["Report Generator"]

    GEN --> COMMUNITY["Community Tier\n(Text / Telegram)"]
    GEN --> PRO["Pro Tier\n(JSON)"]
    GEN --> ENTERPRISE["Enterprise Tier\n(PDF + SIEM JSON)"]

    COMMUNITY --> TG["Telegram Bot\nChannel Alert"]
    COMMUNITY --> STDOUT["Terminal\nstdout"]

    PRO --> FILE_JSON["audit-report.json"]
    PRO --> API_INT["API Integration\nCI/CD Pipelines"]

    ENTERPRISE --> FILE_PDF["audit-report.pdf\n(reportlab branded)"]
    ENTERPRISE --> SIEM["SIEM JSON\n(Splunk / ELK)"]

    style COMMUNITY fill:#43a047,color:#fff
    style PRO fill:#1976d2,color:#fff
    style ENTERPRISE fill:#6a1b9a,color:#fff
```

### Tier Feature Matrix

| Feature | Community | Pro | Enterprise |
|---------|-----------|-----|------------|
| **Format** | Plain text | JSON | PDF + SIEM JSON |
| **Delivery** | stdout / Telegram | File / API | File / SIEM ingest |
| **Threat Summary** | Yes | Yes | Yes |
| **Per-File Details** | Top 10 | All | All |
| **Risk Score Breakdown** | Overall only | Per-layer | Per-layer + trend |
| **Quarantine Records** | Count | Full records | Full records + timeline |
| **Threat Intel Status** | Last update time | Source details | Source details + freshness |
| **Remediation Advice** | Basic | Detailed | Detailed + AI-generated |
| **Configuration Audit** | No | Partial | Full dump |
| **Database Metrics** | No | Yes | Yes + historical |
| **Branding** | N/A | N/A | smilinTux branded header |
| **Compliance Mapping** | No | No | SOC2 / NIST references |

---

## 7. Key Management Service (KMS)

The sovereign KMS provides hierarchical key management without
depending on HashiCorp Vault (BSL) or MinIO KES (AGPL).

```mermaid
flowchart TB
    PASS["Passphrase\n(operator input)"] --> SCRYPT["scrypt\nN=2^20, r=8, p=1"]
    SCRYPT --> MASTER["Master Key\n(sealed at rest)"]

    MASTER --> HKDF1["HKDF-SHA256\ncontext: team_id"]
    HKDF1 --> TEAM["Team Key"]

    TEAM --> HKDF2["HKDF-SHA256\ncontext: agent_id"]
    HKDF2 --> AGENT["Agent Key"]

    AGENT --> WRAP["AES-256-GCM\nKey Wrapping"]
    WRAP --> DEK["Data Encryption Key\n(random 32 bytes)"]

    DEK --> ENCRYPT["Encrypt Data\nAES-256-GCM"]
    DEK --> FUSE["FUSE Mount\nEncrypted Volume"]

    subgraph DEPLOY["Deployment Modes"]
        SOCK["Unix Socket\n~/.sksecurity/kms.sock"]
        DOCKER["Docker Swarm\nSidecar + Secrets API"]
        K8S["Kubernetes\nInit Container / Sidecar"]
        PROXMOX["Proxmox LXC\ncloud-init provisioning"]
    end

    AGENT --> DEPLOY

    subgraph AUDIT["Immutable Audit Log"]
        SEAL["seal/unseal events"]
        ROT["key rotation events"]
        DER["key derivation events"]
        REV["key revocation events"]
    end

    KMS_OP["KMS Operations"] --> AUDIT
    AUDIT --> DB[("SQLite audit_log")]

    style MASTER fill:#d32f2f,color:#fff
    style TEAM fill:#ef6c00,color:#fff
    style AGENT fill:#1976d2,color:#fff
    style DEK fill:#388e3c,color:#fff
```

### Key Hierarchy Properties

| Level | Derivation | Purpose | Compromise Impact |
|-------|-----------|---------|-------------------|
| **Master** | scrypt from passphrase + salt | Root of trust | Total (rotate all) |
| **Team** | HKDF-SHA256 from Master + team_id | Isolate teams | Team-scoped only |
| **Agent** | HKDF-SHA256 from Team + agent_id | Per-agent isolation | Single agent only |
| **DEK** | os.urandom(32), wrapped by Agent key | Encrypt actual data | Single data object |

---

## 8. Secret Guard Pipeline

The SecretGuard module prevents credential leaks via pre-commit hooks,
directory scanning, and real-time text checking.

```mermaid
flowchart LR
    subgraph TRIGGER["Trigger"]
        HOOK["git pre-commit\nhook"]
        CLI_CMD["sksecurity guard\nscan /path"]
        TXT["sksecurity guard\ntext 'AKIA...'"]
        STAGED["sksecurity guard\nstaged"]
    end

    subgraph ENGINE["Detection Engine"]
        REGEX["14 Built-in Patterns\nAWS, GitHub, npm,\nOpenAI, Slack, Stripe,\nJWT, private keys,\nDB URLs, ..."]
        ENTROPY["Entropy Scoring\nHigh-entropy strings"]
        CONTEXT["Context Filter\nSkip test files,\nexamples, comments"]
        AI_CHECK["AI Severity\nAssessment\n(optional)"]
    end

    subgraph RESULT["Result"]
        BLOCK["BLOCK COMMIT\nexit code 1"]
        PASS_OK["ALLOW\nexit code 0"]
        FINDING["SecretFinding\ntype, severity,\nredacted_text,\nremediation"]
    end

    TRIGGER --> REGEX
    REGEX --> ENTROPY
    ENTROPY --> CONTEXT
    CONTEXT -->|"findings"| AI_CHECK
    CONTEXT -->|"no findings"| PASS_OK
    AI_CHECK --> FINDING
    FINDING -->|"CRITICAL/HIGH"| BLOCK
    FINDING -->|"MEDIUM/LOW"| PASS_OK

    style BLOCK fill:#d32f2f,color:#fff
    style PASS_OK fill:#388e3c,color:#fff
```

---

## 9. Quarantine Case Study: `unhinged-mode`

This case study demonstrates the scanner working as designed: correctly
identifying security-relevant content and acting on it, then being
overridden by the infrastructure owner after manual review.

### What Happened

The `unhinged-mode` skill in `~/clawd/skills/` was auto-quarantined
during a daily audit scan. The scanner flagged it with a risk score
above 80 based on multiple threat pattern matches.

### Why It Was Flagged

```mermaid
flowchart TD
    SKILL["~/clawd/skills/unhinged-mode/"] --> SCAN["SecurityScanner\nDaily Audit"]

    SCAN --> F1["Pattern: jailbreak keywords\nSeverity: HIGH\nConfidence: 0.85"]
    SCAN --> F2["Pattern: abliterate keywords\nSeverity: HIGH\nConfidence: 0.80"]
    SCAN --> F3["Pattern: execSync usage\nSeverity: CRITICAL\nConfidence: 0.95"]
    SCAN --> F4["Pattern: SSH command strings\nSeverity: HIGH\nConfidence: 0.75"]

    F1 --> SCORE["Composite Risk Score: 87/100"]
    F2 --> SCORE
    F3 --> SCORE
    F4 --> SCORE

    SCORE --> THRESHOLD{">= 80?"}
    THRESHOLD -->|"Yes (87)"| WL_CHECK{"In whitelist.json?"}
    WL_CHECK -->|"No"| QUARANTINE["AUTO-QUARANTINE\nMoved to ~/clawd/quarantine/"]
    QUARANTINE --> RECORD["QuarantineRecord written\nSHA256 hash computed\nTelegram alert sent"]

    style QUARANTINE fill:#d32f2f,color:#fff
    style SCORE fill:#ef6c00,color:#fff
```

### What the Scanner Detected

| Finding | Pattern Type | Severity | Why It Triggered |
|---------|-------------|----------|------------------|
| Jailbreak keywords | `jailbreak\|DAN\|ignore previous` | HIGH | Content references jailbreak techniques (legitimate research) |
| Abliterate keywords | `abliterate\|uncensor\|unfilter` | HIGH | References model uncensoring (intentional feature) |
| `execSync` usage | `execSync\(` | CRITICAL | Node.js synchronous shell execution detected |
| SSH command strings | `ssh\s+.*@` | HIGH | SSH connection commands in skill scripts |

### Resolution

The infrastructure owner (Chef/David) reviewed the quarantined skill and
determined that all flagged patterns were intentional and legitimate:

- **Jailbreak/abliterate references** are the skill's purpose (authorized
  AI research environment)
- **execSync** is used for local automation on sovereign infrastructure
- **SSH commands** connect to owned machines in the homelab

The skill was added to `whitelist.json` and restored:

```json
{
  "whitelist": ["unhinged-mode"],
  "reviewed_by": "Chef",
  "reviewed_at": "2026-03-10T12:00:00Z",
  "reason": "Authorized sovereign AI research skill. All flagged patterns are intentional."
}
```

### Why This Is a Feature

This case demonstrates every layer of the security architecture working
correctly:

1. **Detection** -- The scanner correctly identified security-relevant
   content. `execSync` and SSH commands ARE security-sensitive operations,
   regardless of intent.
2. **Automated response** -- The system did not wait for a human. It
   quarantined first, asked questions later.
3. **Operator override** -- The whitelist mechanism gives the infrastructure
   owner final authority. The system enforces security by default but
   respects sovereignty.
4. **Audit trail** -- Every step (scan, flag, quarantine, whitelist, restore)
   is logged in SQLite with timestamps.
5. **No false negative** -- A system that never flags legitimate-but-dangerous
   code would also miss actual attacks using the same patterns.

> The correct behavior for a security system is to flag first and let
> the operator decide. A scanner that silently ignores `execSync` and
> SSH patterns would be broken.

---

## 10. AI Safety Content Detection (NSFW/Jailbreak Scanner)

SKSecurity is unique among security tools in that it scans for **AI model
safety bypass patterns** — not just traditional vulnerabilities like SQLi or
XSS, but the emerging threat landscape of prompt injection, model abliteration,
jailbreak toolkits, and NSFW content generation pipelines.

No other open-source security scanner provides this capability.

### Why This Matters

As AI agents become infrastructure (running as services, managing data,
executing code), the attack surface shifts:

- **Traditional threat**: attacker exploits a buffer overflow in your web server
- **AI-era threat**: attacker ships a "helpful plugin" that removes your model's
  safety guardrails, injects system prompts, or abliterates refusal weights

These attacks look nothing like traditional malware. They look like:
- Python libraries with names like `abliterate.py` or `liberation.py`
- Shell scripts that inject text into `CLAUDE.md` or system prompts
- GGUF model files with `-unhinged` suffixes
- Config files mapping providers to `"injection": "system_prompt"`

Traditional scanners (ClamAV, Snyk, Trivy) will never flag these. They scan
for CVEs and known malware signatures. SKSecurity scans for **intent patterns**
specific to the AI agent ecosystem.

### Detection Categories

```mermaid
graph LR
    subgraph "Traditional Security"
        T1[CVE/NVD Patterns]
        T2[Secret Leaks]
        T3[Dependency Vulns]
        T4[Code Injection]
    end

    subgraph "AI Safety Detection 🆕"
        A1[Jailbreak Toolkits]
        A2[Model Abliteration]
        A3[Prompt Injection Infra]
        A4[Safety Bypass Keywords]
        A5[NSFW Generation Pipelines]
        A6[Uncensored Model Variants]
    end

    T1 & T2 & T3 & T4 --> SCANNER["SKSecurity\nScanner"]
    A1 & A2 & A3 & A4 & A5 & A6 --> SCANNER

    SCANNER --> SCORE[Risk Score 0-100]
    SCORE --> REPORT[Three-Tier Report]

    style A1 fill:#e91e63,color:#fff
    style A2 fill:#e91e63,color:#fff
    style A3 fill:#e91e63,color:#fff
    style A4 fill:#e91e63,color:#fff
    style A5 fill:#e91e63,color:#fff
    style A6 fill:#e91e63,color:#fff
```

### AI Safety Threat Patterns

| Pattern | Regex / Heuristic | Severity | Real-World Example |
|---------|-------------------|----------|--------------------|
| Jailbreak toolkit | `jailbreak\|DAN\|ignore previous\|you are now` | HIGH | DAN prompts, Crescendo attacks |
| Model abliteration | `abliterate\|uncensor\|unfilter\|remove refusal` | HIGH | Arditi et al. refusal direction removal |
| Prompt injection infra | `system_prompt.*inject\|CLAUDE\.md.*inject` | CRITICAL | L1B3RT4S liberation prompt system |
| NSFW generation | `nsfw\|explicit\|uncensored.*model\|adult.*content` | HIGH | Uncensored Stable Diffusion pipelines |
| Safety bypass configs | `guardrail\|safety.*off\|filter.*disable` | MEDIUM | Model config overrides |
| Uncensored model files | `\-unhinged\|\-uncensored\|\-abliterated` | HIGH | Ollama model variants with safety removed |
| Weight surgery tools | `refusal.*direction\|activation.*steering` | HIGH | Mechanistic interpretability exploits |
| Reverse proxy injection | `proxy.*inject\|middleware.*system.*prompt` | CRITICAL | Man-in-the-middle prompt injection |

### Sovereign Override: The Whitelist

The critical insight: **not all AI safety bypasses are attacks**.

Legitimate use cases exist for every pattern above:
- **Security researchers** need jailbreak tools to test model robustness
- **Creative teams** need uncensored models for authentic fiction
- **Infrastructure owners** have the right to configure their own systems

SKSecurity solves this with the **whitelist + audit trail** pattern:

1. Scanner flags the content (correctly — it IS security-relevant)
2. Auto-quarantine isolates it (safe default)
3. Owner reviews and whitelists (sovereignty preserved)
4. Audit trail records the decision (compliance maintained)
5. Future scans skip whitelisted items (no repeated false positives)

This is the only security scanner that understands the difference between
"this looks dangerous" and "this IS dangerous" in the context of AI agent
infrastructure — and gives the operator the tools to make that distinction.

### SIEM Integration for AI Safety Events

Enterprise customers get AI safety events in the SIEM JSON export:

```json
{
  "event_type": "ai_safety_bypass_detected",
  "severity": "HIGH",
  "source": "skill_scanner",
  "description": "Model abliteration toolkit detected in skill 'unhinged-mode'",
  "metadata": {
    "skill_name": "unhinged-mode",
    "patterns_matched": ["abliterate", "jailbreak", "execSync", "ssh"],
    "risk_score": 87,
    "action_taken": "quarantined",
    "whitelist_status": "pending_review"
  }
}
```

This feeds directly into SOC dashboards, SOAR playbooks, and compliance
reporting — giving security teams visibility into AI-specific threats that
no other tool provides.

---

## 11. File Map

Quick reference for the source files that implement each component.

| Component | Source File | Entry Point |
|-----------|------------|-------------|
| Core Scanner | `sksecurity/scanner.py` | `SecurityScanner.scan_path()` |
| Threat Intelligence | `sksecurity/intelligence.py` | `ThreatIntelligence()` |
| Quarantine Manager | `sksecurity/quarantine.py` | `QuarantineManager.quarantine()` |
| Secret Guard | `sksecurity/secret_guard.py` | `SecretGuard.scan_directory()` |
| KMS | `sksecurity/kms.py` | `KMS()` (seal/unseal/derive) |
| Email Screener | `sksecurity/email_screener.py` | `EmailScreener.screen()` |
| Runtime Monitor | `sksecurity/monitor.py` | `RuntimeMonitor()` |
| Truth Engine | `sksecurity/truth_engine.py` | `TruthEngine.verify()` |
| Database | `sksecurity/database.py` | `SecurityDatabase()` |
| PDF Reports | `sksecurity/pdf_report.py` | `generate_audit_pdf()` |
| AI Client | `sksecurity/ai_client.py` | `AIClient()` |
| CLI | `sksecurity/cli.py` | `sksecurity` command |
| MCP Server | `sksecurity/mcp_server.py` | `sksecurity-mcp` command |
| Dashboard | `sksecurity/dashboard.py` | `sksecurity dashboard` |
| Config | `sksecurity/config.py` | `SecurityConfig.load()` |
| Daily Audit | `scripts/daily_security_audit.py` | `SecurityAuditor()` |
| Advanced System | `scripts/advanced_security_system.py` | `AdvancedSecuritySystem()` |
| Skill Scanner | `scripts/scan_skill.py` | `SecurityScanner.scan_skill()` |
| Threat Updater | `scripts/update_threats.py` | updates `threat_cache.json` |
| Inference Gateway | `src/gateway.mjs` | AI inference proxy with CapAuth |

---

## Related Documents

- **[SKSENTRY.md](SKSENTRY.md)** — Crowdsourced AI threat intelligence design
- **[INFERENCE-GATEWAY.md](INFERENCE-GATEWAY.md)** — AI inference proxy appliance (BlueCoat for AI) with CapAuth identity, policy engine, DLP, and model-specific adapters
