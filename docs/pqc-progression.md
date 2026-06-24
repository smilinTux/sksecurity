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

## 2026-06-24 — Entry #3: Q4 at-rest → hybrid key-wrap AVAILABLE + fingerprint-keying bug FIXED  🔐 *(per-store / opt-in)*

Phase 1 / Q4 (plan §3 S11 / §5 Phase 1 / §6 Q4) landed in code: new `skchat/src/skchat/atrest_wrap.py` (`wrap_dek`/`unwrap_dek`, versioned + suite-tagged) + a refactor of `skchat/src/skchat/encrypted_store.py` (`DekManager`, hybrid-wrapped random DEK, back-compat read + `migrate_store()`). Two things shipped together:

1. **Fingerprint-keying bug fixed (classical, independent of quantum).** The at-rest store previously derived its data-encryption key (DEK) from the PGP **fingerprint** via HKDF — a low-entropy, often *public* value, so the encryption was effectively keyed by something non-secret. The DEK is now **high-entropy random** (`os.urandom(32)`), generated once and persisted **wrapped** (cleartext DEK never touches disk). The only secret is a locally-held hybrid recipient **private key** (0600). `StorageKeyDeriver` survives **only** for back-compat reads / migration.
2. **At-rest HNDL fix.** The DEK is sealed with the hybrid **X25519 + ML-KEM-768** KEM (`skcomms.pqkem`, `HKDF(X25519‖ML-KEM-768)` combiner, liboqs) via `atrest_wrap.wrap_dek` — the same idiom as Q2's `group_ratchet.wrap_epoch_secret`. The wrapped DEK stays secret unless **both** primitives break, so a harvested encrypted store / backup is not retroactively decryptable after a CRQC. Bulk cipher stays AES-256-GCM (Grover-only, untouched). The wrap blob is `MAGIC || version || suite_id || hybrid_ct || nonce || wrapped` — versioned and suite-tagged for Q0 agility; `describe_blob()` reports the suite without the private key.

| Surface | Suite | Status |
|---|---|---|
| identity | `ed25519-v1` | classical |
| envelope-sig | `ed25519-v1` | classical |
| group-key (hybrid-migrated group) | `x25519-mlkem768` | hybrid-pq |
| group-key (default / un-migrated group) | `rsa-pgp-wrap-v1` | classical |
| at-rest (hybrid-wrapped store) | `x25519-mlkem768` | **hybrid-pq** |
| at-rest (un-migrated / bulk only) | `aes256-gcm-v1` | symmetric |

**No data loss — proven round-trip.** Existing encrypted stores stay **readable**: open with the legacy fingerprint key supplied and old content decrypts via fallback; `EncryptedChatHistory.migrate_store()` re-wraps every message under the new random+hybrid-wrapped DEK (decrypt-old → re-encrypt-new), preserving plaintext **exactly**. Tests prove: write under old scheme → migrate → read back identical; DEK ≠ any fingerprint-derived key; malformed/tampered/truncated/bad-version blobs raise `AtRestWrapFormatError`; the 19 pre-existing `test_encrypted_store.py` tests stay green.

**Honest scope — AVAILABLE, not the global default.** The hybrid wrap is **per-store and opt-in**: `EncryptedChatHistory.from_identity()` now creates new stores with a hybrid-wrapped DEK, but existing stores are not auto-migrated. The self-report reflects **reality per store** (`EncryptedChatHistory.crypto_self_report()` / `sksecurity.pqc_report.atrest_surface_for(store)`); the **default** `build_report()` keeps the at-rest surface at the `aes256-gcm-v1` symmetric baseline until stores migrate. **Covered now:** the skchat at-rest chat store. **Follow-up (same wrap layer, not yet wired):** skmem-pg dumps, memory flat-file trees, and the capauth root-key backup — `atrest_wrap.wrap_dek` is the building block; wiring those sealers is the remaining Q4 surface work.

Next milestones: wire the wrap layer over skmem-pg dumps / memory trees / root-key backup; Q5 (`sk_pqc` — app-side hybrid PQC); then fleet migration so the *default* at-rest + group-key lines flip to hybrid-pq.
