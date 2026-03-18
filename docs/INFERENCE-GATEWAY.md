# SKSecurity Inference Gateway

> A BlueCoat-style proxy appliance for AI inference — authentication, authorization, audit, and policy enforcement for every model call.

## Problem

Organizations running AI agents face a new infrastructure gap: **there is no security layer between agents and the models they call.** Every inference request — containing potentially sensitive prompts, tool calls, and data — goes directly to model providers with nothing but an API key.

Traditional API gateways (Kong, Envoy, nginx) don't understand AI-specific concerns:
- They can't distinguish a harmless completion from a jailbreak attempt
- They don't track tool-call chains across multi-turn agent sessions
- They can't enforce per-agent model budgets or tool-level ACLs
- They can't detect leaked secrets in outbound prompts or PII in inbound responses

The SKSecurity Inference Gateway is **the missing security layer for AI inference.**

## Architecture

```
┌─────────────────────────────────────┐
│        Agent Framework              │
│  (OpenClaw, LangChain, CrewAI, etc) │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│   SKSecurity Inference Gateway      │
│                                     │
│  ┌───────────┐  ┌────────────────┐  │
│  │  Identity  │  │  Policy Engine │  │
│  │  (CapAuth) │  │  (YAML rules)  │  │
│  └─────┬─────┘  └───────┬────────┘  │
│        │                 │           │
│  ┌─────▼─────────────────▼────────┐  │
│  │       Request Pipeline          │  │
│  │  auth → policy → adapt → log    │  │
│  └─────┬──────────────────────────┘  │
│        │                             │
│  ┌─────▼─────────────────────────┐   │
│  │    Model-Specific Adapters     │   │
│  │  ┌─────────┐ ┌──────────────┐ │   │
│  │  │ Anthropic│ │ NVIDIA NIM   │ │   │
│  │  │ (clean)  │ │ (compensate) │ │   │
│  │  └─────────┘ └──────────────┘ │   │
│  │  ┌─────────┐ ┌──────────────┐ │   │
│  │  │ Ollama   │ │ OpenRouter   │ │   │
│  │  │ (local)  │ │ (multi)      │ │   │
│  │  └─────────┘ └──────────────┘ │   │
│  └───────────────────────────────┘   │
│                                      │
│  ┌────────────────────────────────┐  │
│  │         Audit Logger            │  │
│  │  Structured JSON • PGP-signed   │  │
│  └────────────────────────────────┘  │
└──────────────┬───────────────────────┘
               │
               ▼
┌──────────────────────────────────────┐
│     Model Providers                   │
│  Anthropic │ NVIDIA │ Ollama │ etc   │
└──────────────────────────────────────┘
```

## Core Capabilities

### 1. Identity-Based Authentication (CapAuth)

Every inference request is cryptographically authenticated using PGP-based identity — not API keys, not OAuth tokens, not JWTs.

```
Request Header:
  X-CapAuth-DID: did:skcapstone:lumina
  X-CapAuth-Sig: <PGP detached signature of request body>
  X-CapAuth-Timestamp: 2026-03-12T14:30:00Z
```

The gateway verifies:
1. **Identity**: DID resolves to a known agent in the PMA (Person-Machine Alliance)
2. **Signature**: Request body matches the PGP signature (tamper detection)
3. **Freshness**: Timestamp within tolerance window (replay protection)
4. **Membership**: Agent's PMA tier determines allowed models and tools

No third-party identity provider. No token rotation. No revocation lists. The PGP web of trust IS the authorization layer.

### 2. Policy Engine

YAML-based policy rules evaluated per-request:

```yaml
# policy.yaml
policies:
  - name: agent-model-acls
    description: Control which agents can use which models
    rules:
      - agent: lumina
        allow_models: ["*"]  # Queen gets everything
        max_tokens_per_day: 500000

      - agent: gtd-ops
        allow_models: ["ollama/*", "nvidia/moonshotai/kimi-k2-instruct"]
        deny_models: ["anthropic/claude-opus*"]  # Too expensive for GTD
        max_tokens_per_day: 50000

      - agent: security-ops
        allow_models: ["anthropic/claude-opus*", "nvidia/*"]
        allow_tools: ["sksecurity_*", "read", "exec"]
        deny_tools: ["message", "sessions_send"]  # No comms access

      - agent: comms-ops
        allow_models: ["nvidia/*", "ollama/*"]
        deny_tools: ["exec"]  # No shell access
        max_tokens_per_day: 100000

  - name: cost-controls
    description: Prevent runaway inference costs
    rules:
      - condition: model.cost.output > 50  # $/M tokens
        action: require_confirmation
        message: "High-cost model requested by {agent}"

      - condition: daily_spend > 10.00
        action: block
        message: "Daily spend limit exceeded"

  - name: content-policies
    description: DLP and content safety
    rules:
      - direction: outbound
        scan_for: [api_keys, passwords, private_keys, ssn, credit_card]
        action: redact_and_warn

      - direction: inbound
        scan_for: [pii, internal_ips, file_paths]
        action: log_and_flag
```

### 3. Model-Specific Adapters

Each model provider has different quirks. The adapter layer compensates:

| Adapter | Behavior |
|---------|----------|
| **Anthropic** | Clean pass-through. Native tool calling, streaming, extended thinking all preserved. Audit logging only. |
| **NVIDIA NIM** | Full compensation layer (proven in production). Tool reduction (94→16), thinking suppression, content sanitization, stream normalization, ghost tool call detection. |
| **Ollama** | Local pass-through. No auth needed. Add structured logging. Handle model-specific chat templates. |
| **OpenRouter** | Multi-model routing. Normalize response formats. Handle provider-specific error codes. |

The adapter pattern means adding a new provider is one file — implement `adapt(request)` and `normalize(response)`.

### 4. Audit Trail

Every request/response is logged as structured JSON, optionally PGP-signed for tamper evidence:

```json
{
  "id": "req_a8f3b2c1",
  "timestamp": "2026-03-12T14:30:00.123Z",
  "agent": {
    "did": "did:skcapstone:lumina",
    "name": "Queen Lumina",
    "pma_tier": "sovereign"
  },
  "request": {
    "model": "anthropic/claude-opus-4-6",
    "provider": "anthropic",
    "tools_requested": 94,
    "tools_allowed": 94,
    "prompt_tokens": 1250,
    "contains_secrets": false,
    "policy_result": "allow"
  },
  "response": {
    "completion_tokens": 340,
    "tool_calls": [
      {"name": "read", "args": {"path": "/home/cbrd21/clawd/security/config/whitelist.json"}},
      {"name": "exec", "args": {"command": "sksecurity scan ."}}
    ],
    "latency_ms": 2340,
    "contains_pii": false
  },
  "cost": {
    "input_cost": 0.01875,
    "output_cost": 0.0255,
    "total_cost": 0.04425
  },
  "pgp_signature": "-----BEGIN PGP SIGNATURE-----\n..."
}
```

### 5. Data Loss Prevention (DLP)

Outbound prompt scanning catches secrets before they reach model providers:

| Pattern | Category | Action |
|---------|----------|--------|
| `sk-[a-zA-Z0-9]{48}` | OpenAI API Key | Redact |
| `nvapi-[a-zA-Z0-9_-]{64}` | NVIDIA API Key | Redact |
| `ghp_[a-zA-Z0-9]{36}` | GitHub PAT | Redact |
| `AKIA[0-9A-Z]{16}` | AWS Access Key | Redact |
| `-----BEGIN.*PRIVATE KEY-----` | Private Key | Block |
| `[0-9]{3}-[0-9]{2}-[0-9]{4}` | SSN Pattern | Redact |
| High entropy strings (>4.5 bits/char) | Potential secrets | Flag |

This reuses SKSecurity's existing Secret Guard pattern library (14 categories with entropy scoring).

## Differentiation

### vs. LiteLLM / Portkey / Helicone

| Feature | LiteLLM | Portkey | SKSecurity Gateway |
|---------|---------|---------|-------------------|
| Multi-provider routing | Yes | Yes | Yes |
| API key auth | Yes | Yes | **PGP identity (CapAuth)** |
| Per-agent policies | No | Basic | **Full YAML policy engine** |
| Model-specific adapters | Basic | No | **Active compensation** (proven with NVIDIA) |
| DLP / Secret scanning | No | No | **Yes (Secret Guard integration)** |
| Agent hierarchy awareness | No | No | **Yes (parent→subagent cascading)** |
| Self-hosted / sovereign | Partial | No (SaaS) | **Yes (systemd service)** |
| Audit PGP signing | No | No | **Yes (tamper-proof)** |
| Open source | Yes | No | **Yes (GPL-3.0)** |

### vs. Traditional API Gateways (Kong, Envoy)

Traditional gateways operate at the HTTP level. They see requests and responses but don't understand:
- Tool-call semantics (which tools an agent is invoking and why)
- Multi-turn conversation context (is this the 3rd retry of a failing tool call?)
- Model-specific behaviors (Kimi leaks thinking tokens, Llama ignores parallel_tool_calls)
- AI-specific DLP (secrets in natural language prompts, PII in model responses)

The SKSecurity Gateway operates at the **AI inference level** — it understands what agents are doing, not just what HTTP requests they're making.

## Implementation Roadmap

### Phase 1: Adapter Refactor (Foundation)
Extract nvidia-proxy.mjs into modular adapter pattern.

```
src/
  gateway.mjs              # Main proxy server
  adapters/
    base.mjs               # Adapter interface
    nvidia.mjs             # NVIDIA NIM adapter (extracted from nvidia-proxy.mjs)
    anthropic.mjs          # Anthropic adapter (clean pass-through + audit)
    ollama.mjs             # Ollama adapter (local, no auth)
  middleware/
    router.mjs             # Route by model prefix to correct adapter
    logger.mjs             # Structured JSON audit logging
  config/
    gateway.yaml           # Gateway configuration
```

**Deliverable**: Same functionality as current nvidia-proxy.mjs, but extensible. Anthropic requests pass through cleanly. Ollama requests route locally.

### Phase 2: CapAuth Integration
Add PGP-based identity verification to the request pipeline.

```
src/
  middleware/
    capauth.mjs            # PGP signature verification
    identity.mjs           # DID resolution and PMA membership check
  config/
    agents.yaml            # Agent identity registry
```

**Deliverable**: Every request authenticated by agent DID. Unsigned requests rejected (configurable: strict mode vs. audit-only mode).

### Phase 3: Policy Engine
YAML-based policy rules with per-agent model/tool ACLs and cost controls.

```
src/
  middleware/
    policy.mjs             # Policy evaluation engine
  config/
    policy.yaml            # Policy rules (model ACLs, tool ACLs, cost limits)
```

**Deliverable**: Granular control over which agents can use which models and tools. Cost ceiling enforcement. Daily token budgets.

### Phase 4: DLP and Content Scanning
Integrate Secret Guard patterns for prompt/response scanning.

```
src/
  middleware/
    dlp.mjs                # Data Loss Prevention scanner
  config/
    dlp-patterns.yaml      # Secret patterns (reuse from Secret Guard)
```

**Deliverable**: Outbound prompts scanned for secrets/credentials before reaching providers. Inbound responses scanned for PII. Configurable actions: redact, block, flag, log.

### Phase 5: Dashboard and Observability
Real-time monitoring dashboard.

```
src/
  dashboard/
    index.html             # Dashboard UI (host locally or on GitHub Pages)
    api.mjs                # Dashboard API endpoints
  middleware/
    metrics.mjs            # Prometheus-compatible metrics
```

**Deliverable**: Real-time view of inference traffic, per-agent costs, tool-call heatmaps, latency percentiles, policy violations.

## Deployment

The gateway runs as a systemd user service (same as the current nvidia-proxy):

```ini
[Unit]
Description=SKSecurity Inference Gateway
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/node /home/user/sksecurity/src/gateway.mjs
Environment=GATEWAY_PORT=18780
Environment=CONFIG_DIR=/home/user/sksecurity/config
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

Zero external dependencies. No Docker required. No cloud services. Runs on the same box as the agent framework.

## Configuration

```yaml
# gateway.yaml
server:
  port: 18780
  host: 127.0.0.1

providers:
  anthropic:
    target: https://api.anthropic.com
    adapter: anthropic
    auth: env:ANTHROPIC_API_KEY

  nvidia:
    target: https://integrate.api.nvidia.com/v1
    adapter: nvidia
    auth: env:NVIDIA_API_KEY

  ollama:
    target: http://192.168.0.100:11434/v1
    adapter: ollama
    auth: none

identity:
  mode: capauth          # capauth | api-key | none
  pma_roster: /path/to/pma-roster.json
  require_signature: true
  timestamp_tolerance: 300  # seconds

audit:
  enabled: true
  format: json
  output: /var/log/sksecurity/inference.jsonl
  sign_entries: true      # PGP sign each log entry
  pgp_key: /path/to/gateway-key.gpg

dlp:
  enabled: true
  patterns: /path/to/dlp-patterns.yaml
  outbound_action: redact   # redact | block | flag | log
  inbound_action: flag      # redact | block | flag | log
```

## Pricing Model

Follows SKSecurity's three-tier approach:

| Tier | Price | Includes |
|------|-------|----------|
| **Community** | $0 | Gateway, adapters, audit logging, basic policies |
| **Pro** | $0 | + CapAuth integration, DLP scanning, YAML policy engine |
| **Enterprise** | Let's Talk | + Dashboard, SIEM integration, custom adapters, support |

Same code. Same GPL-3.0 license. Enterprise pays for implementation time, not software.

## Why This Matters

Every organization running AI agents will need this layer. Today they're sending raw prompts containing proprietary data through API keys with no audit trail, no identity verification, and no policy enforcement.

The SKSecurity Inference Gateway is the firewall for AI inference. Just like BlueCoat became essential for web traffic inspection in the 2000s, inference proxies will become essential for AI traffic inspection in the 2020s.

The difference: we're building it open source, sovereign-first, and identity-native. No SaaS lock-in. No cloud dependency. Your keys, your policies, your audit trail.

---

*Part of the [SKSecurity](https://github.com/smilinTux/SKSecurity) ecosystem. GPL-3.0.*
