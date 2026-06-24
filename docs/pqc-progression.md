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

## 2026-06-24 — Entry #3: Q3 DM/envelope → hybrid KEM AVAILABLE  🔐 *(per-conversation / opt-in, negotiated)*

Phase 1 / Q3 (plan §3 S4/S6, §5) landed in code: a single shared sealing primitive `skcomms/src/skcomms/pqdm.py` plus hybrid methods on `skcomms/src/skcomms/crypto.py` (`EnvelopeCrypto`) and `skchat/src/skchat/crypto.py` (`ChatCrypto`). A conversation whose recipient advertises a **signed hybrid-KEM prekey** (PQXDH-style `PrekeyBundle`) now wraps the DM / envelope-payload symmetric key via the hybrid **X25519 + ML-KEM-768** KEM (`skcomms.pqkem`, HKDF(X25519‖ML-KEM-768) combiner, liboqs) and AES-256-GCM-seals the body. The ~1.1 KB KEM ciphertext rides in the (first) message; the sealed blob is `ct(1120) ‖ nonce(12) ‖ aesgcm(body)`, stored under a `pqdm1:` scheme prefix in the existing `content` field (no model change). **Downgrade-lock:** the negotiated suite + the (sender, recipient) pair are bound into the AEAD AAD, so a man-in-the-middle that strips the hybrid prekey to force a classical downgrade cannot do so silently — the recipient's open fails (`DowngradeDetected`) and/or the recorded `negotiated_suite` flips to classical, which the per-conversation self-report surfaces.

| Surface | Suite | Status |
|---|---|---|
| identity | `ed25519-v1` | classical |
| envelope-sig | `ed25519-v1` | classical |
| group-key (hybrid-migrated group) | `x25519-mlkem768` | **hybrid-pq** |
| group-key (default / un-migrated group) | `rsa-pgp-wrap-v1` | classical |
| **dm / envelope-payload (hybrid-negotiated conversation)** | `x25519-mlkem768` | **hybrid-pq** |
| **dm / envelope-payload (classical-only peer / downgraded)** | `x25519-pgp-wrap-v1` | classical |
| at-rest | `aes256-gcm-v1` | symmetric |

**Honest scope — AVAILABLE, opt-in, negotiated.** Hybrid engages **only when both sides advertise it** (this side supports liboqs AND the recipient published a hybrid prekey). A classical-only peer keeps the existing PGP path **byte-for-byte unchanged** — `EnvelopeCrypto.encrypt_payload`/`ChatCrypto.encrypt_message` are untouched; the hybrid path is additive (`*_hybrid` / `*_auto` methods). The runtime self-report reflects **reality per conversation** (`sksecurity.pqc_report.conversation_surface_for(negotiated_suite, kind, peer)`); the **default** `build_report()` still shows these surfaces classical until conversations actually negotiate hybrid. So: the *primitive and per-conversation path are live*, but **do not claim the DM/envelope surface is hybrid-pq globally** until peers publish prekeys and the self-report says so. The prekey **signature stays classical** (Phase 2 / Q7 migrates it); only the KEM is quantum-resistant here.

**Flutter contract:** the native `sk_pqc` client must publish a `PrekeyBundle` `{suite:"x25519-mlkem768", hybrid_public_hex:<1216-byte hybrid pub>, signature, key_id}` in its key bundle and decapsulate sealed blobs with its 2432-byte hybrid private key. Web PWA (no WebCrypto PQC) advertises no prekey → negotiated classical downgrade (reduced-assurance leg, per plan §3.1).

Next milestones: Q4 (at-rest → hybrid key-wrap), Q5 (`sk_pqc` — app-side hybrid PQC + prekey publication), then a fleet migration so the *default* DM/envelope + group-key lines flip to hybrid-pq.
