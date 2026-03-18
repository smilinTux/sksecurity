# SKSecurity — One-Pager

**The first open-source security scanner with AI safety content detection.**

---

## The Problem

AI agents are now infrastructure. They execute code, manage data, and make
decisions. But every security scanner on the market — ClamAV, Snyk, Trivy,
Semgrep — was built for traditional threats. None of them can detect jailbreak
toolkits, model abliteration scripts, prompt injection pipelines, or NSFW
generation infrastructure.

**The AI threat landscape is invisible to existing tools.**

---

## What SKSecurity Does

Multi-layer security scanning purpose-built for AI agent ecosystems:

- **AI safety content detection** — jailbreak toolkits, model abliteration,
  prompt injection, NSFW pipelines, uncensored model variants, safety bypass configs
- **Traditional security** — code injection, secrets, vulnerable dependencies,
  deserialization, path traversal
- **Automated quarantine** — high-risk findings are isolated immediately,
  SHA256-hashed, logged, and reported via Telegram
- **Sovereign override** — whitelist mechanism lets operators approve flagged
  items after review, preserving audit trail
- **Integrity verification** — call-home system with signed manifests detects
  tampering in deployed agent code

---

## Key Differentiators

| SKSecurity | Traditional Scanners |
|------------|---------------------|
| Detects jailbreak, abliteration, prompt injection | Blind to AI-specific threats |
| Four-layer scoring (static + behavioral + dependency + AI) | Single-method analysis |
| Auto-quarantine with operator override | Alert-only or block-only |
| SKSentry crowdsourced threat intelligence | Vendor-controlled signatures |
| MCP server for AI assistant integration | No AI workflow integration |
| Sovereign KMS (no Vault/KES dependency) | Requires external KMS |
| Three-tier reports (text, JSON, PDF+SIEM) | Single output format |

---

## By the Numbers

| Metric | Value |
|--------|-------|
| AI safety threat patterns | 8 categories (jailbreak, abliteration, prompt injection, NSFW, safety bypass, uncensored models, weight surgery, proxy injection) |
| Secret detection patterns | 14 built-in (AWS, GitHub, npm, OpenAI, Slack, Stripe, JWT, private keys, DB URLs, more) |
| Risk score layers | 4 (static 40%, behavioral 25%, dependency 20%, AI 15%) |
| Threat intel sources | 3 (Moltbook, NVD, GitHub Advisories) + built-in pattern library |
| Report tiers | 3 (Community free, Pro JSON, Enterprise PDF+SIEM) |
| Entry points | 5 (CLI, Python API, MCP server, web dashboard, systemd timer) |
| Production-tested on | 68+ AI skills in daily automated audits |

---

## Pricing

| Community | Pro | Enterprise |
|-----------|-----|------------|
| **Free** (open-source, GPL-3.0) | Contact for pricing | Contact for pricing |
| Text reports + Telegram alerts | JSON reports for CI/CD | PDF + SIEM JSON (Splunk/ELK) |
| Full scanning + quarantine | Per-layer risk breakdown | SOC2/NIST compliance mapping |
| GitHub community support | Email support | Dedicated support + custom branding |

---

## Get Started

```bash
pip install sksecurity
sksecurity init
sksecurity scan ./your-ai-project
```

**GitHub**: [github.com/smilinTux/SKSecurity](https://github.com/smilinTux/SKSecurity)
| **PyPI**: [pypi.org/project/sksecurity](https://pypi.org/project/sksecurity/)
| **npm**: [@smilintux/sksecurity](https://www.npmjs.com/package/@smilintux/sksecurity)

---

*Built by smilinTux.org as part of the SKCapstone sovereign agent framework.
Dogfooded daily on production AI agent infrastructure.*
