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

Phase 1 / Q3 (plan §3 S4/S6, §5) landed in code: a single shared sealing primitive `skcomms/src/skcomms/pqdm.py` plus hybrid methods on `skcomms/src/skcomms/crypto.py` (`EnvelopeCrypto`) and `skchat/src/skchat/crypto.py` (`ChatCrypto`). A conversation whose recipient advertises a **signed hybrid-KEM prekey** (PQXDH-style `PrekeyBundle`) now wraps the DM / envelope-payload symmetric key via the hybrid **X25519 + ML-KEM-768** KEM (`skcomms.pqkem`, HKDF(X25519‖ML-KEM-768) combiner, liboqs) and AES-256-GCM-seals the body. The ~1.1 KB KEM ciphertext rides in the (first) message; sealed blob `ct(1120) ‖ nonce(12) ‖ aesgcm(body)`, stored under a `pqdm1:` scheme prefix in the existing `content` field. **Downgrade-lock:** the negotiated suite + (sender, recipient) are bound into the AEAD AAD, so a MITM that strips the hybrid prekey can't downgrade silently — the recipient's open fails (`DowngradeDetected`) and/or `negotiated_suite` flips classical, which the per-conversation self-report surfaces.

**Honest scope — opt-in, negotiated.** Hybrid engages **only when both sides advertise it**. A classical-only peer keeps the existing PGP path byte-for-byte unchanged (the hybrid path is additive `*_hybrid`/`*_auto`). The prekey **signature stays classical** (Phase 2 / Q7); only the KEM is quantum-resistant here. **Flutter contract:** native `sk_pqc` publishes a `PrekeyBundle{suite:"x25519-mlkem768", hybrid_public_hex:<1216 B>, signature, key_id}` and decapsulates with its 2432-byte hybrid private key; the web PWA (no WebCrypto PQC) advertises no prekey → negotiated classical downgrade (reduced-assurance leg).

## 2026-06-24 — Entry #4: Q4 at-rest → hybrid key-wrap AVAILABLE + fingerprint-keying bug FIXED  🔐 *(per-store / opt-in)*

Phase 1 / Q4 landed: new `skchat/src/skchat/atrest_wrap.py` (`wrap_dek`/`unwrap_dek`, versioned + suite-tagged) + a refactor of `encrypted_store.py` (`DekManager`, hybrid-wrapped random DEK, back-compat read + `migrate_store()`). Two fixes shipped together:
1. **Fingerprint-keying bug fixed (classical).** The DEK was HKDF-derived from the PGP **fingerprint** — a low-entropy, often *public* value. It is now **high-entropy random** (`os.urandom(32)`), persisted **wrapped** (cleartext DEK never touches disk); the only secret is a locally-held hybrid private key (0600).
2. **At-rest HNDL fix.** The DEK is sealed with hybrid **X25519 + ML-KEM-768** (`atrest_wrap.wrap_dek`) — secret unless **both** primitives break, so a harvested store/backup is not retroactively decryptable. Bulk cipher stays AES-256-GCM.

**No data loss.** Existing stores stay readable (legacy fingerprint-key fallback); `migrate_store()` re-wraps each message under the new DEK, preserving plaintext exactly (proven by round-trip tests; the 19 pre-existing `test_encrypted_store.py` tests stay green). **Covered now:** the skchat at-rest chat store. **Follow-up:** skmem-pg dumps, memory trees, capauth root-key backup (same `wrap_dek` layer).

### Current posture (per-surface availability — Phase 1 complete)

| Surface | Suite | Status |
|---|---|---|
| identity | `ed25519-v1` | classical |
| envelope-sig | `ed25519-v1` | classical |
| group-key (hybrid-migrated) | `x25519-mlkem768` | **hybrid-pq** |
| group-key (default / un-migrated) | `rsa-pgp-wrap-v1` | classical |
| dm / envelope (hybrid-negotiated) | `x25519-mlkem768` | **hybrid-pq** |
| dm / envelope (classical-only / downgraded) | `x25519-pgp-wrap-v1` | classical |
| at-rest (hybrid-wrapped store) | `x25519-mlkem768` | **hybrid-pq** |
| at-rest (un-migrated / bulk only) | `aes256-gcm-v1` | symmetric |

**🏁 Phase-1 harvest-now-decrypt-later surfaces all have a hybrid path AVAILABLE** (group-key, DM/envelope, at-rest — opt-in/negotiated/per-store). The **default** `build_report()` stays classical until peers publish prekeys + groups/stores migrate — the self-report reflects reality, never overclaims.

Next milestones: Q5 (`sk_pqc` app-side hybrid PQC + prekey publication → flips the app onto the hybrid path), wire the at-rest wrap over skmem-pg / memory / root-key backup, then a fleet migration so the *default* lines flip to hybrid-pq. Phase 2 = signatures/identity (Q6/Q7).
