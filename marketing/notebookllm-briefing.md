# SKSecurity — Comprehensive Briefing Document

*Optimized for NotebookLLM audio generation. Information-dense with
conversational anchors for natural podcast-style discussion.*

---

## What Is SKSecurity?

SKSecurity is an open-source security scanner built specifically for AI agent
infrastructure. It's the first tool of its kind — a security scanner that
understands AI-specific threats like jailbreak toolkits, model abliteration
scripts, prompt injection pipelines, and NSFW content generation
infrastructure.

Think of it this way: you probably already run security tools on your
codebase. Maybe Snyk for dependency vulnerabilities, maybe Trivy for
container scanning, maybe ClamAV for malware. Those tools are great at what
they do. But none of them have ever seen a jailbreak. None of them know what
it means when a Python file is named `abliterate.py` and contains functions
that surgically remove refusal behavior from language model weights. None of
them will flag a config file that maps a reverse proxy to inject system
prompts into AI conversations.

SKSecurity fills that gap. It combines traditional security scanning —
pattern matching, dependency analysis, secret detection — with a dedicated
AI safety content detection engine that recognizes the emerging threat
landscape of the AI era.

---

## Why Now? The Timing Problem.

Here's what's happening in 2025 and 2026: AI agents are becoming
infrastructure. Not toys, not demos — actual infrastructure. Companies are
deploying AI agents as services that manage data, execute code, interact
with customers, and make operational decisions. These agents run on
traditional servers, but they introduce attack surfaces that traditional
security tools were never designed to see.

The attack surface shift looks like this. In the traditional world, an
attacker exploits a buffer overflow in your web server. In the AI era, an
attacker ships a "helpful plugin" that removes your model's safety
guardrails, injects system prompts to change its behavior, or abliterates
its refusal weights so it will comply with any request.

And here's the alarming part: these attacks look nothing like traditional
malware. A jailbreak toolkit is just a Python script. An abliteration tool
is a machine learning notebook. A prompt injection pipeline is a YAML config
file. Traditional scanners will give every one of these a clean bill of
health. They scan for CVEs and known malware signatures. They don't scan
for intent patterns.

The security industry has a massive blind spot, and it's growing wider every
day as AI agent deployment accelerates.

---

## What Does the Scanner Actually Detect?

SKSecurity scans for two categories of threats simultaneously.

The first category is traditional security threats — the stuff other
scanners handle. Code injection patterns like `eval()` and `exec()`.
Command injection via `os.system()` and `shell=True`. Hardcoded secrets
and API keys (14 built-in patterns covering AWS, GitHub, npm, OpenAI,
Slack, Stripe, JWT tokens, private keys, database URLs). Vulnerable
dependencies. Deserialization risks. Path traversal. SQL injection.

The second category is where SKSecurity stands alone: AI safety content
detection. This includes:

**Jailbreak toolkits** — scripts containing DAN prompts, Crescendo attack
patterns, "ignore previous instructions" sequences, and other techniques
for bypassing model safety guardrails.

**Model abliteration** — tools and libraries that perform weight surgery on
language models to permanently remove refusal behavior. This is a real
technique from the AI safety research community (Arditi et al.) that has
been weaponized. An abliterated model will comply with any request —
including generating harmful content, providing dangerous instructions, or
bypassing every safety guardrail the model creator put in place.

**Prompt injection infrastructure** — configuration files and middleware
that inject text into AI system prompts. This is the man-in-the-middle
attack of the AI era. If someone can inject text into the system prompt
that governs an AI agent's behavior, they control the agent.

**NSFW generation pipelines** — configurations for uncensored image and
text generation models. These often appear as Stable Diffusion configs
or Ollama model files with `-unhinged` or `-uncensored` suffixes.

**Safety bypass configurations** — YAML or JSON files that disable
guardrails, turn off safety filters, or override model safety settings.

**Weight surgery tools** — scripts that manipulate model activations,
specifically targeting what researchers call "refusal directions" in the
model's weight space. These are mechanistic interpretability techniques
being used offensively.

---

## How Does the Scoring Work?

The scanner produces a composite risk score from 0 to 100 using four
analysis layers, each with a different weight:

Static pattern matching accounts for 40% of the score. This is regex-based
detection against the threat pattern database — both traditional patterns
and AI safety patterns.

Behavioral heuristics account for 25%. This looks at runtime behavior
patterns: Is SSL verification disabled? Are there path traversal patterns
in file writes? Is there dynamic code execution?

Dependency analysis accounts for 20%. This checks for known-vulnerable
packages, suspicious imports, and typosquatting in package names.

AI-powered analysis accounts for the remaining 15%. If an Ollama or
OpenAI-compatible model is available locally, SKSecurity will send code
snippets for contextual analysis. This layer degrades gracefully — if no
AI is available, the other three layers still produce a reliable score.

---

## The Quarantine System

When a scan produces a risk score of 80 or above, SKSecurity's quarantine
system activates. The flagged file or directory is physically moved out of
its active location into a quarantine directory. A SHA256 hash of every
quarantined file is computed and stored. A quarantine record is written to
a JSON log. And a Telegram alert is sent to the operator with the skill
name, risk score, and matched patterns.

This is the "quarantine first, ask questions later" design philosophy. The
system doesn't wait for human approval to isolate a high-risk finding. It
acts immediately and lets the operator review after the fact.

But — and this is a critical design decision — SKSecurity includes a
sovereign override mechanism. The operator can review a quarantined item,
determine that it's intentional (maybe it's a legitimate security research
tool, or a creative writing skill that needs uncensored output), and add
it to the whitelist. Once whitelisted, future scans skip that item. But
the audit trail records everything: the original flag, the quarantine, the
review, and the whitelist decision.

This is security with sovereignty. The system enforces safe defaults but
respects the operator's authority over their own infrastructure.

---

## The Real-World Case Study

This isn't theoretical. SKSecurity caught a real AI safety tool during a
production scan.

The setup: a sovereign AI research lab runs 68+ AI skills — plugins that
give AI agents capabilities like code execution, file management, web
access, communication. These skills are scanned daily by SKSecurity via a
systemd timer.

During one of these automated scans, the scanner flagged a skill called
`unhinged-mode` with a risk score of 87 out of 100. The findings were:
jailbreak keywords (HIGH severity, 0.85 confidence), abliteration keywords
(HIGH, 0.80), execSync usage (CRITICAL, 0.95), and SSH command strings
(HIGH, 0.75).

The skill was auto-quarantined. A Telegram alert fired. The infrastructure
owner reviewed the quarantine and determined that all flagged patterns were
intentional — the jailbreak and abliteration references were the skill's
entire purpose (authorized AI research), execSync was used for local
automation, and the SSH commands connected to machines in the owner's
homelab.

The owner whitelisted the skill with a review note: "Authorized sovereign
AI research skill. All flagged patterns are intentional."

This case study demonstrates every layer of the architecture working
correctly. The scanner found security-relevant content. It quarantined
automatically. The operator reviewed and overrode. The audit trail
captured the complete decision chain. And critically — a scanner that
silently ignores `execSync` and jailbreak patterns would be broken. Those
are genuinely dangerous patterns. The correct behavior is to flag them and
let the operator decide.

---

## SKSentry: Crowdsourced AI Threat Intelligence

You know how CrowdSec does participative security for IP reputation? SKSentry
does the same thing but for AI threats. It is the crowdsourced threat
intelligence layer of SKSecurity — when one instance detects a new AI threat,
every instance gets protected.

Today, SKSecurity pulls threat intelligence from three sources: Moltbook
(curated AI-specific threat signatures), NIST's National Vulnerability
Database (CVEs), and GitHub Security Advisories. This data flows through a
normalization layer, gets deduplicated, and lands in a local SQLite
database that the scanner consults on every scan. There's also a JSON
cache file for offline fallback when upstream sources are unreachable.

SKSentry expands this into a community threat-sharing network. When one
operator's scanner detects a new jailbreak variant or a novel abliteration
technique, that pattern — anonymized and normalized — gets shared with the
community. Every SKSecurity installation benefits from every other
installation's discoveries.

This is how you scale AI security beyond what any single organization can
maintain. No vendor controls the signature database. The community does.

---

## Architecture and Integration Points

SKSecurity is designed to fit into existing workflows, not replace them.
It has five entry points:

A command-line interface for direct scanning, quarantine management, secret
detection, and report generation. A Python API for embedding security
checks into existing applications. An MCP server (Model Context Protocol,
stdio transport) that lets Claude and other AI assistants call security
tools directly — your AI can scan its own infrastructure. A Flask-based
web dashboard for visual event management and on-demand scanning. And a
systemd timer integration for fully automated daily audits.

The data layer is SQLite — no external database dependency. Reports come
in three tiers: Community (plain text and Telegram, free), Pro (structured
JSON for CI/CD pipelines), and Enterprise (branded PDF with SIEM-ready
JSON for Splunk and ELK, plus SOC2 and NIST compliance mapping).

There's also a sovereign Key Management Service built in — hierarchical
key derivation (Master, Team, Agent, Data Encryption Key) using
scrypt, HKDF-SHA256, and AES-256-GCM. No dependency on HashiCorp Vault
(BSL licensed) or MinIO KES (AGPL).

---

## The Origin Story

SKSecurity was built by a sovereign AI research lab — a small operation
that actually runs AI agents in production. Not as a proof of concept. As
daily infrastructure. Multiple AI agents with different personalities and
capabilities, running on a mix of local hardware and cloud infrastructure,
coordinated by a framework called SKCapstone.

The security scanner was born out of necessity. When you're running 68+
AI skills that give agents the ability to execute code, manage files, send
messages, and interact with external services — you need to know what's
in those skills. You need to know if someone slipped a prompt injection
into a config file. You need to know if a dependency update introduced an
abliteration script. You need to know before it runs, not after.

So the team built a scanner. And then they realized: nobody else has one.
Not open-source, anyway. There are enterprise AI security products
emerging, but nothing open-source, nothing community-driven, and nothing
that combines traditional security scanning with AI safety content
detection in a single tool.

The scanner has been dogfooded on its own infrastructure since day one.
Every daily audit runs against the lab's own skills directory. The
unhinged-mode quarantine case study? That's a real event from real
production use.

---

## Why This Is Pioneering

The traditional application security market is worth over $10 billion.
Companies like Veracode, Checkmarx, Qualys, and Rapid7 built massive
businesses on one insight: even if your application has built-in security,
you need independent third-party validation.

The same logic applies to AI security, but the third-party validation
layer doesn't exist yet. AI frameworks like OpenClaw are building
internal security features — sandboxing, keyword detection, guardrails.
But these are self-assessments by the framework vendor. Enterprises need
independent validation for the same reasons they need independent
security audits of their traditional infrastructure: trust, compliance,
and the blind spots that come from auditing your own work.

SKSecurity is the third-party validation layer for AI agent ecosystems.
It works with any framework — OpenClaw, AutoGPT, LangChain, custom
deployments. It provides the independent security assessment that
enterprises require for SOC2, NIST, and board-level risk reporting.

And it does something no other tool does: it scans for AI-specific
threats. Jailbreak toolkits, model abliteration, prompt injection
infrastructure, NSFW generation pipelines. The threats that are invisible
to every traditional scanner on the market.

---

## How to Get Started

Installation is one line:

```
pip install sksecurity
```

Initialize in your project:

```
sksecurity init
```

Run your first scan:

```
sksecurity scan ./your-ai-project
```

The GitHub repository is at github.com/smilinTux/SKSecurity. It's
GPL-3.0-or-later. Star it, fork it, contribute threat patterns,
submit scanner rules, test SIEM integrations, or just run it on your
own AI infrastructure and see what it finds.

The security of AI agents is too important to be proprietary.

---

*SKSecurity is part of the SKCapstone sovereign agent framework.
Built by smilinTux.org.*
