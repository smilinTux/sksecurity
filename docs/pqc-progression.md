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

## 2026-06-24 — Entry #2: Q2 group-key → hybrid epoch-ratchet AVAILABLE  🔐 *(per-group / opt-in)*

Phase 1 / Q2 (the marquee HNDL item, plan §3 S5 / §5) landed in code: `skchat/src/skchat/group_ratchet.py` + a refactor of `group.py` (`GroupChat`/`GroupKeyDistributor`/`rotate_key`/`remove_member`). A group whose `kem_suite == "x25519-mlkem768"` now distributes a **per-epoch** secret wrapped to each member with the hybrid **X25519 + ML-KEM-768** KEM (`skcomms.pqkem`, HKDF(X25519‖ML-KEM-768) combiner, liboqs), and derives per-message keys by a symmetric HKDF ratchet from the epoch secret (AES-256-GCM bulk unchanged). Re-key on member add/remove + a 50-msg / 7-day bound → forward secrecy (removed members can't read new epochs) + post-compromise security (a leaked epoch secret reveals nothing about the next epoch). PQ material is paid **once per epoch**, not per message (no 33× ML-KEM bloat).

| Surface | Suite | Status |
|---|---|---|
| identity | `ed25519-v1` | classical |
| envelope-sig | `ed25519-v1` | classical |
| group-key (hybrid-migrated group) | `x25519-mlkem768` | **hybrid-pq** |
| group-key (default / un-migrated group) | `rsa-pgp-wrap-v1` | classical |
| at-rest | `aes256-gcm-v1` | symmetric |

**Honest scope — this is AVAILABLE, not yet the global default.** The hybrid ratchet is **per-group and opt-in**: it only engages for groups whose `kem_suite` is `x25519-mlkem768`. Existing groups remain on the classical `rsa-pgp-wrap-v1` suite (unchanged, HNDL-exposed) until explicitly rotated via `GroupChat.migrate_to_hybrid()`. The runtime self-report reflects **reality per group** (`GroupChat.crypto_self_report()` / `sksecurity.pqc_report.group_surface_for(group)`); the **default** `build_report()` still shows the group-key surface as `classical`, because most groups have not migrated. Members lacking a hybrid-KEM key fall back gracefully (skipped in hybrid distribution; the report flags the gap). So: the *primitive and the per-group path are live*, but **do not claim the group-key surface is hybrid-pq globally** until groups are migrated and the fleet self-report says so.

Next milestones: Q3 (DM/envelope → hybrid KEM), Q4 (at-rest → hybrid key-wrap), Q5 (`sk_pqc` — app-side hybrid PQC), then a fleet migration so the *default* group-key line flips to hybrid-pq.
