# SKSecurity Demo Video Script

**Target length:** 2-3 minutes
**Tone:** Conversational, technical but accessible, slightly irreverent
**Format:** Screen recording with voiceover

---

## INTRO (0:00 - 0:20)

**[VISUAL: Terminal on dark background. SKSecurity logo/ASCII art.]**

**VOICEOVER:**

"Your security scanner has a blind spot. It catches CVEs, it catches
hardcoded AWS keys, it catches SQL injection. But it has never seen a
jailbreak toolkit. It doesn't know what model abliteration looks like. And
it will give a clean bill of health to a prompt injection pipeline.

SKSecurity fixes that."

---

## INSTALL (0:20 - 0:35)

**[VISUAL: Terminal. Type the commands live.]**

**VOICEOVER:**

"Installation takes one line."

```bash
pip install sksecurity
```

**[VISUAL: pip install output scrolling]**

"Initialize it in your project."

```bash
sksecurity init
```

**[VISUAL: Show the generated sksecurity.yml config file briefly]**

"That's it. You're ready to scan."

---

## SCAN (0:35 - 1:10)

**[VISUAL: Terminal. Run scan against a directory with AI skills.]**

**VOICEOVER:**

"Let's scan a directory of AI agent skills. These are real plugins that
agents use to interact with the world — code execution, file management,
web access, the works."

```bash
sksecurity scan ~/clawd/skills/ --quarantine --threshold 80
```

**[VISUAL: Scan output scrolling. Show the progress as it processes
directories. Highlight the risk scores appearing for each skill.]**

"SKSecurity runs four analysis layers on every file: static pattern matching,
behavioral heuristics, dependency analysis, and optional AI-powered
contextual analysis. Each layer contributes to a composite risk score
from zero to a hundred."

**[VISUAL: Highlight a skill coming back with risk score 87. Show the
individual findings — jailbreak keywords, abliteration patterns, execSync.]**

"Here's one that scored 87. The scanner found jailbreak keywords,
abliteration references, synchronous shell execution, and SSH command
strings. Any traditional scanner would have missed all four of those."

---

## QUARANTINE (1:10 - 1:35)

**[VISUAL: Quarantine notification in terminal output. Then show the
quarantine directory.]**

**VOICEOVER:**

"Because we passed `--quarantine` with a threshold of 80, that skill just
got auto-quarantined. Moved out of the active directory, SHA256-hashed for
integrity, and logged."

```bash
sksecurity quarantine list
```

**[VISUAL: Show quarantine list output with the flagged skill, hash, timestamp,
and risk score.]**

"A Telegram alert just went out to the operator. The skill is isolated. No
human had to be in the loop — quarantine first, ask questions later."

**[VISUAL: Quick flash of a Telegram notification with the alert message.]**

---

## WHITELIST (1:35 - 1:55)

**[VISUAL: Terminal. Show the whitelist review flow.]**

**VOICEOVER:**

"But here's the thing — this particular skill is intentional. It's a
legitimate AI research tool on sovereign infrastructure. The operator
reviews it and adds it to the whitelist."

```bash
sksecurity quarantine restore <id> --whitelist --reason "Authorized AI research skill"
```

**[VISUAL: Show the restore confirmation and whitelist entry.]**

"The skill is back. Future scans will skip it. But the audit trail records
every step — the flag, the quarantine, the review, the whitelist decision.
Security with sovereignty. That's the design."

---

## REPORT (1:55 - 2:20)

**[VISUAL: Show report generation.]**

**VOICEOVER:**

"Now let's generate the audit report."

```bash
sksecurity audit --output report.pdf
```

**[VISUAL: Brief flash of the PDF report — branded header, threat summary,
quarantine records, risk scores. Then show the JSON output.]**

"Three tiers. Community gets text and Telegram alerts — free. Pro gets
structured JSON you can pipe into your CI/CD. Enterprise gets branded PDFs
with SIEM-ready JSON that feeds directly into Splunk or ELK."

**[VISUAL: Quick side-by-side of text output, JSON output, and PDF report.]**

"SOC2 and NIST compliance mapping included at the Enterprise tier. Your
auditors will love you."

---

## SECRET DETECTION BONUS (2:20 - 2:35)

**[VISUAL: Terminal. Quick demo.]**

**VOICEOVER:**

"One more thing. SKSecurity also catches secrets — 14 built-in patterns
for API keys, tokens, and credentials."

```bash
sksecurity guard scan ./src
sksecurity guard install   # pre-commit hook
```

**[VISUAL: Show a secret finding — redacted API key, file path, line number,
remediation suggestion.]**

"Install the pre-commit hook and secrets never make it to your repo. Period."

---

## CLOSE (2:35 - 2:50)

**[VISUAL: Terminal with install command. GitHub URL. Logo.]**

**VOICEOVER:**

"SKSecurity. The first open-source security scanner that knows what a
jailbreak looks like. Install it in thirty seconds. Scan your AI
infrastructure for threats that every other tool misses.

`pip install sksecurity`. GitHub link in the description."

**[VISUAL: Fade to logo and GitHub URL: github.com/smilinTux/SKSecurity]**

---

## Production Notes

- **Screen recording software**: OBS or asciinema for terminal captures
- **Terminal theme**: Dark background, high-contrast text (Dracula or similar)
- **Font size**: Large enough to read on mobile (16pt+ in terminal)
- **Pacing**: Don't rush the scan output — let viewers see the findings populate
- **B-roll options**: Architecture diagram from docs, mermaid diagrams rendered
- **Music**: Subtle electronic/ambient underneath, not distracting
- **Thumbnail text**: "Your Security Scanner Can't See AI Threats" with risk score graphic
