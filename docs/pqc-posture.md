# PQC Posture — coverage self-report

`sksecurity pqc-posture` scans the six security surfaces of the sovereign-comms
ecosystem and reports, per surface, **whether hybrid-PQ is the default, merely
available, or absent** — grounded in the real wire-tags, never an out-of-band
assumption, and never overclaiming.

This is the *coverage* view. For per-object suite detail use
[`pqc-report`](./pqc-progression.md); for the whole-ecosystem rollup use
`pqc-dashboard`.

## The three postures

| Posture | Meaning |
|---|---|
| `hybrid-pq` | hybrid X25519 + ML-KEM-768 (FIPS 203) is the **unconditional default** for new objects on this surface |
| `gated` | a hybrid path **exists and is wired**, but it is opt-in / capability-negotiated / per-object migration — you get classical unless both sides advertise it |
| `classical` | **no PQ path** on this surface today (Shor-breakable asymmetric, or a classical channel underlay) |

The classifier is pure: `classify_posture(default_is_hybrid, hybrid_available)`
→ `hybrid-pq` if hybrid is the default, else `gated` if it merely exists, else
`classical`. "Available" never rounds up to "default".

## The six surfaces and their real wire-tags

| Surface | Wire-tag(s) | Hybrid suite | Source |
|---|---|---|---|
| `dm-ratchet` | `pqdr1` (RFC-0001 P1 capability) | `x25519-mlkem768` | skchat `DmRatchet` / `pq_prekeys.RATCHET_CAP` |
| `group` | `kem_suite` | `x25519-mlkem768` | skchat `GroupChat` epoch ratchet |
| `metadata` | `aqid:` + `pqroute1` | `x25519-mlkem768` | skcomms `anon_transport` / `pqroute` |
| `identity-sig` | `sig_suite` | `mldsa65-ed25519-v2` | capauth / skcomms `SignedEnvelope` |
| `at-rest` | `wrap_suite` | `x25519-mlkem768` | skchat `encrypted_store` DEK wrap |
| `transport` | channel (WireGuard / TLS 1.3, X25519) | — | skcomms federated envelope transport |

`metadata` pairs two real primitives: `aqid:` no-identity unlinkable addressing
(`aqid-v1`, deniable HMAC-SHA256 — authenticity without non-repudiation, no body
confidentiality) and `pqroute1`, which hybrid-seals the inner routing metadata +
content so a harvest-now-decrypt-later relay cannot link who-talks-to-whom.

`transport` is reported `classical` honestly: the channel underlay keys with
classical X25519. Post-quantum confidentiality on this ecosystem comes from the
**message layer** (dm-ratchet / group / pqroute1 / at-rest), not the channel — so
the transport surface does not borrow the message layer's posture.

## Usage

```bash
sksecurity pqc-posture            # live: up-rates group/at-rest from real objects
sksecurity pqc-posture --static   # honest default coverage (no live enrichment)
sksecurity pqc-posture --format json
```

**Live mode** is best-effort and can only **up-rate** from unambiguous evidence:
`group` flips to `hybrid-pq` only when *every* existing group is hybrid; `at-rest`
flips when this operator's store actually seals its DEK with `x25519-mlkem768`.
The transport surface is never enriched (no PQ leg exists to find).

## Honesty discipline

Per `sk-standards/CRYPTOGRAPHY_STANDARD.md`: the report never emits
"quantum-proof" / "quantum-safe" / "unbreakable" / unconditional "end-to-end
post-quantum" (enforced by `FORBIDDEN_TERMS` + the repo's own `claims` gate). A
hybrid leg is secure **iff EITHER** the X25519 leg **or** the ML-KEM-768 (FIPS
203) leg holds — that is the entire claim. AES-256-GCM bulk is symmetric
(Grover-only, quantum-acceptable, not quantum-broken); signatures are
future-forgery exposure, not retroactive (not HNDL).

Module: `sksecurity/pqc_posture.py` · Tests: `tests/test_pqc_posture.py`.
