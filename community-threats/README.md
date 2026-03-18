# SKSentry — Community Threat Feed

Community-powered AI threat defense.

This repository contains shared threat patterns, blocklists, and reputation
data used by [SKSecurity](https://github.com/smilinTux/SKSecurity) instances
worldwide. SKSentry is the crowdsourced threat intelligence layer of
SKSecurity — when one instance detects a new AI threat, every instance
gets protected.

---

## Quick Start

### Pull Patterns (no account needed)

```bash
# Update your SKSecurity instance with community patterns
sksecurity update --sources community
```

That's it. Your scanner now includes community-reported patterns for jailbreak
toolkits, abliteration scripts, prompt injection infrastructure, and more.

### Submit a Signal (opt-in)

```bash
# Scan and share anonymized detections with the community
sksecurity scan ~/path/to/skills/ --share
```

Signals are anonymized before submission. Only regex patterns and categorical
metadata are shared -- never file contents, paths, or identifying information.
See [Privacy](#privacy) below.

---

## Repository Structure

```
sksecurity-threats/
  patterns/
    ai-safety.json        # AI-specific threat patterns
    traditional.json      # Traditional security patterns (CVE, secrets, injection)
  blocklist/
    skills.json           # SHA256 hashes of known-malicious skills
  allowlist/
    verified.json         # Community-verified safe skills
  reputation/
    counters.json         # Pattern confidence counters
  schema.json             # JSON Schema for pattern validation
  .github/
    workflows/
      process-signal.yml  # Automated signal processing
```

## Pattern Categories

### AI Safety Patterns

Patterns that no traditional scanner detects:

| Type | What It Catches | Example |
|------|----------------|---------|
| `ai_jailbreak_toolkit` | DAN prompts, system prompt overrides | "ignore previous instructions" |
| `ai_model_abliteration` | Refusal direction removal | abliterate.py, liberation.py |
| `ai_prompt_injection` | Prompt injection infrastructure | CLAUDE.md injection scripts |
| `ai_safety_bypass` | Guardrail disabling | "safety.*off", "filter.*disable" |
| `ai_nsfw_pipeline` | Uncensored content generation | Explicit SD pipelines |
| `ai_uncensored_model` | Models with safety removed | *-unhinged.gguf, *-abliterated |
| `ai_weight_surgery` | Activation steering exploits | Refusal direction vectors |
| `ai_proxy_injection` | MITM prompt injection | Reverse proxy system prompt injection |

### Traditional Patterns

Standard security patterns, enhanced with community confidence scores:

| Type | What It Catches |
|------|----------------|
| `code_injection` | eval(), exec(), dynamic code execution |
| `command_injection` | os.system(), subprocess with shell=True |
| `hardcoded_secrets` | API keys, tokens, private keys |
| `remote_code_execution` | curl\|bash, pipe-to-shell |
| `deserialization` | Unsafe pickle, YAML |
| `obfuscated_code` | Hex encoding, base64 obfuscation |
| `reverse_shell` | Socket-based reverse shells |

---

## Privacy

### What IS Shared (in signals)

- The regex pattern that matched
- Pattern type and severity (categorical)
- SHA256 hash of matched content (one-way)
- Context type: `skill`, `plugin`, `model`, `config`
- Anonymized instance ID (salted hash)
- Timestamp

### What is NEVER Shared

- File paths or directory structures
- File contents or source code
- Hostnames, IPs, or usernames
- Skill names or project names
- Agent configurations
- Any PII

### Opt-In Only

Signal submission requires the explicit `--share` flag. Reading the feed
requires nothing -- it is a public repository.

---

## Contributing

### Submit a New Pattern

1. Fork this repository
2. Add your pattern to the appropriate file in `patterns/`
3. Validate against `schema.json`
4. Open a Pull Request with:
   - Pattern regex
   - Description of what it detects
   - At least one real-world reference or example
   - Suggested severity and confidence

### Report a False Positive

If a pattern is flagging legitimate code in your environment:

1. Open an Issue with the label `false-positive`
2. Include the pattern ID (e.g., `ai-safety-003`)
3. Describe why it is a false positive in your context
4. The reputation system will reduce that pattern's confidence

### Report a New Threat

If you have found an AI-specific threat not covered by existing patterns:

1. Open an Issue with the label `new-threat`
2. Describe the threat (what it does, how it works)
3. Provide a regex pattern if possible
4. Suggest severity and category

---

## Versioning

Pattern feeds are tagged with semantic versions:

- `v1.x` -- Read-only feed (Phase 1)
- `v2.x` -- Signal submission + reputation (Phase 2-3)

Pin to a major version in your config if you want stability:

```yaml
community:
  feed_url: "https://raw.githubusercontent.com/smilinTux/sksecurity-threats/v1/patterns"
```

---

## License

Pattern data in this repository is released under
[CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).
You are free to use, share, and adapt the patterns with attribution.

Scripts and tooling are released under the MIT License.

---

## Related Projects

- [SKSecurity](https://github.com/smilinTux/SKSecurity) -- The scanner that consumes these patterns
- [CrowdSec](https://www.crowdsec.net/) -- IP reputation network (inspiration for SKSentry's participative model)
- [MITRE ATLAS](https://atlas.mitre.org/) -- Adversarial Threat Landscape for AI Systems
