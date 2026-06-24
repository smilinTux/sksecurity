# PQC Progression Ledger

Historical record of the SK ecosystem's quantum-resistance posture — current vs. as we enable hybrid PQC, surface by surface. Append a dated snapshot whenever a surface flips `classical → hybrid-pq`. Epic `PQC-MIGRATION` (coord `e1d6ba2a`); tooling: `sksecurity pqc-report`.

Legend: `classical` = Shor-breakable (vulnerable) · `symmetric` = AES-256/SHA-2 (already quantum-acceptable) · `hybrid-pq` = X25519+ML-KEM-768 (target).

---

## 2026-06-23 — Entry #1: PRE-PQC BASELINE  🏁 *(the starting line)*

Phase Q0 complete (crypto-agility scaffolding) — every surface is suite-id tagged but **no algorithm migrated yet**. This is the honest day-zero posture we measure all progress against.

| Surface | Suite | Status |
|---|---|---|
| identity | `ed25519-v1` | classical |
| envelope-sig | `ed25519-v1` | classical |
| group-key | `rsa-pgp-wrap-v1` | classical |
| at-rest | `aes256-gcm-v1` | symmetric |

**Posture:** 1/4 quantum-resistant · 3 classical · 1 symmetric. **NOT quantum-resistant end-to-end** — all asymmetric surfaces are classical. PQC migration not started.

Next milestones to record here: Q2 (group-key → hybrid epoch-ratchet), Q3 (DM/envelope → hybrid KEM), Q4 (at-rest → hybrid key-wrap), Q5 (`sk_pqc` — app-side hybrid PQC).

