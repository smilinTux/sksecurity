# SKSecurity Pitch Deck

*The first open-source security scanner that sees AI threats.*

---

## Slide 1: The Problem

### AI Agents Are Infrastructure Now. Your Scanner Doesn't Know That.

Organizations are deploying AI agents as services — managing data, executing
code, interacting with users, making decisions. These agents run on top of
traditional infrastructure but introduce an entirely new attack surface.

**The gap:**

- ClamAV scans for known malware signatures. It has never seen a jailbreak toolkit.
- Snyk checks your dependency tree for CVEs. It doesn't know what model abliteration is.
- Trivy scans container images. It can't detect a prompt injection pipeline.

Traditional security tools are blind to the emerging AI threat landscape.
They were built for a world where the attacker targets your server, not your model.

> "We ran Trivy, Snyk, and ClamAV on a directory containing a jailbreak toolkit,
> an abliteration script, and an NSFW generation pipeline. Zero findings."

---

## Slide 2: The Threat Landscape

### New Threats That Look Nothing Like Traditional Malware

| Threat | What It Looks Like | What It Does |
|--------|--------------------|--------------|
| **Jailbreak toolkits** | Python scripts with DAN prompts, Crescendo attacks | Bypasses model safety guardrails entirely |
| **Model abliteration** | Libraries named `abliterate.py`, weight surgery scripts | Permanently removes refusal behavior from model weights |
| **Prompt injection infra** | Config files mapping `"injection": "system_prompt"` | Man-in-the-middle attacks on AI conversations |
| **NSFW generation pipelines** | Uncensored Stable Diffusion configs, `-unhinged` model files | Produces harmful or illegal content at scale |
| **Safety bypass configs** | YAML with `guardrail: off`, `safety: disabled` | Silently disables model safety features |
| **Uncensored model variants** | GGUF files with `-uncensored`, `-abliterated` suffixes | Models with safety training removed |

These attacks don't exploit buffer overflows. They exploit trust. And every
traditional scanner on the market will give them a clean bill of health.

---

## Slide 3: What SKSecurity Does

### Multi-Layer Scanning with AI Safety Awareness

SKSecurity combines traditional security scanning with a dedicated AI safety
content detection engine. Four analysis layers produce a composite risk score
from 0-100:

| Layer | Weight | What It Catches |
|-------|--------|-----------------|
| **Static pattern matching** | 40% | Jailbreak keywords, abliteration scripts, code injection, secrets |
| **Behavioral heuristics** | 25% | SSL bypass, path traversal, dynamic code execution patterns |
| **Dependency analysis** | 20% | Vulnerable packages, typosquatting, suspicious imports |
| **AI-powered analysis** | 15% | Contextual threat assessment via local Ollama or OpenAI |

**Three-tier reporting** meets teams where they are:

- **Community** (free): Plain text reports + Telegram alerts
- **Pro**: Structured JSON for CI/CD pipelines and API integration
- **Enterprise**: Branded PDF reports + SIEM JSON (Splunk/ELK) with SOC2/NIST mapping

**Automated response**: Findings above a risk threshold are auto-quarantined,
SHA256-hashed, and logged. The operator gets a Telegram alert in seconds.

---

## Slide 4: SKSentry: Crowdsourced AI Threat Intelligence

### When One Sees a Threat, Everyone's Protected

SKSecurity pulls threat data from three sources today:

1. **Moltbook** — curated AI-specific threat signatures (smilinTux community)
2. **NVD** — NIST's National Vulnerability Database (CVEs)
3. **GitHub Security Advisories** — dependency-level vulnerabilities

The vision: **SKSentry — a community threat-sharing network for AI safety
patterns.** Think CrowdSec, but for AI threats.

When one operator's scanner detects a new jailbreak technique or abliteration
tool, that signature can be shared (anonymized) with the community — so every
SKSecurity installation learns from every other one.

- **SKSentry** crowdsources pattern intelligence for AI safety threats
- Zero infrastructure cost — GitHub repos, Issues, and Actions handle everything
- Community-driven confidence scoring — patterns gain trust as more instances report them

Open-source. Community-driven. No vendor lock-in.

---

## Slide 5: Case Study — Unhinged-Mode Quarantine

### The Scanner Caught a Real AI Safety Tool. That's the Point.

During a daily automated audit of 68+ AI skills, SKSecurity flagged and
auto-quarantined a skill called `unhinged-mode`:

| Finding | Severity | Why It Triggered |
|---------|----------|------------------|
| Jailbreak keywords (`jailbreak`, `DAN`, `ignore previous`) | HIGH | Content references jailbreak techniques |
| Abliteration keywords (`abliterate`, `uncensor`, `unfilter`) | HIGH | References model uncensoring |
| `execSync` usage | CRITICAL | Synchronous shell execution |
| SSH command strings | HIGH | SSH connection commands in scripts |

**Composite risk score: 87/100. Auto-quarantined.**

The infrastructure owner reviewed the quarantine, confirmed all patterns were
intentional (authorized AI research), and whitelisted the skill. The entire
flow was logged in the audit trail.

**Why this matters:**
1. The scanner correctly identified security-relevant content
2. It quarantined first, asked questions later (safe default)
3. The whitelist gave the operator final authority (sovereignty preserved)
4. The audit trail recorded the full decision chain (compliance maintained)
5. A scanner that ignores `execSync` and jailbreak patterns would be broken

> A security tool that never flags legitimate-but-dangerous code will also
> miss actual attacks using the same patterns.

---

## Slide 6: Pricing Tiers

### Three Tiers. Start Free. Scale When You Need To.

| | Community | Pro | Enterprise |
|---|-----------|-----|------------|
| **Price** | Free (open-source) | Contact | Contact |
| **Report format** | Plain text + Telegram | JSON (CI/CD ready) | PDF + SIEM JSON |
| **Threat details** | Top 10 findings | All findings, per-layer breakdown | All findings + trends + AI remediation |
| **Quarantine records** | Count only | Full records | Full records + timeline |
| **Threat intel** | Last update time | Source details | Source details + freshness scores |
| **Configuration audit** | -- | Partial | Full dump |
| **Compliance mapping** | -- | -- | SOC2 / NIST references |
| **Branding** | -- | -- | Custom branded reports |
| **SIEM integration** | -- | -- | Splunk / ELK ingest |
| **Support** | Community (GitHub) | Email | Dedicated |

The Community tier is fully functional. No feature gates on scanning,
quarantine, or threat intelligence. Pro and Enterprise add reporting depth,
integrations, and support.

---

## Slide 7: Architecture Overview

### Built for Extensibility and Sovereignty

```
Entry Points          Core Engine              Outputs
-----------          -----------              -------
CLI                  SecurityScanner          PDF Reports
MCP Server    --->   SecretGuard        --->  JSON Reports
Web Dashboard        ThreatIntelligence       Text/Telegram
Python API           QuarantineManager        SIEM JSON
systemd Timer        Sovereign KMS
                     EmailScreener
                     RuntimeMonitor
                     TruthEngine
```

**Key architectural decisions:**

- **SQLite** for local storage — no external database dependency
- **MCP server** (stdio transport) — Claude and other AI assistants can call
  security tools directly
- **Sovereign KMS** — hierarchical key management (Master > Team > Agent > DEK)
  without HashiCorp Vault or MinIO KES dependencies
- **Offline-capable** — threat cache JSON provides fallback when upstream
  sources are unreachable
- **AI optional** — Ollama/OpenAI analysis enhances scoring but the scanner
  works fully without it

Detailed architecture diagrams: `docs/ARCHITECTURE.md`

---

## Slide 8: Call to Action

### Get Started in 30 Seconds

```bash
pip install sksecurity
sksecurity init
sksecurity scan ./your-ai-project
```

### Join the Community

- **GitHub**: [github.com/smilinTux/SKSecurity](https://github.com/smilinTux/SKSecurity) — star, fork, contribute
- **PyPI**: `pip install sksecurity`
- **npm**: `npm install @smilintux/sksecurity`
- **Website**: [smilintux.org](https://smilintux.org)

### Contribute

We need:
- New AI safety threat patterns (jailbreak variants, new abliteration techniques)
- Scanner rule contributions
- SIEM integration testers
- Documentation and tutorials

SKSecurity is GPL-3.0-or-later. The security of AI agents is too important
to be proprietary.

---

*SKSecurity is part of the SKCapstone sovereign agent framework by smilinTux.org*
