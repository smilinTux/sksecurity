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

## 2026-06-24 — Entry #5: Q5 app-side hybrid PQC LIVE — DMs go hybrid in the BROWSER  🔐🌐 *(per-conversation / negotiated, web-priority)*

Phase 1 / Q5 landed in the Flutter client (`skchat-app`) + the daemon webui (`skchat`), wiring the operator's **actual DMs** onto the hybrid path — including **in the browser**, which is the headline: WebCrypto has no PQC, so the app binds **`sk_pqc`'s noble web backend** (`@noble/post-quantum` ml_kem768, bundled to `web/sk_pqc_noble.js` and exposed as `globalThis.skPqc`) to do real **X25519 + ML-KEM-768** in-page. Native (mobile/desktop) liboqs-FFI sealing is the follow-up; web is the priority since the app runs as a Flutter web build over a tailscale URL.

What shipped:
- **`PqDmCodec` (Dart)** — a byte-for-byte mirror of `skcomms/pqdm.py`: `encap → HKDF-SHA256(info=_INFO_WRAP‖"|"‖aad) → AES-256-GCM(body, aad=downgrade-lock) → ct(1120)‖nonce(12)‖aesgcm` packed under the `pqdm1:x25519-mlkem768:` scheme. The KEM is `sk_pqc` (same `x25519-mlkem768` vector as Q1's `pqkem`); the wrap reuses `package:cryptography` HKDF+AES-GCM.
- **Per-device hybrid keypair**, generated once via `sk_pqc.generateKeyPair()` and persisted in `flutter_secure_storage`, reused across sessions. The app **publishes a `PrekeyBundle`** (`{suite, hybrid_public_hex(1216B), signature, key_id, device_id}`) to the daemon on startup.
- **Prekey store + endpoints** (`skchat/daemon_proxy.py`): `POST /api/v1/prekey` (publish), `GET /api/v1/prekey/{peer}` (fetch). **Lumina publishes her OWN hybrid prekey** (`pq_prekeys.lumina_bundle()`, key generated via `pqkem`, persisted 0600) — so chef-app ↔ Lumina negotiates hybrid. The send path opens an inbound `pqdm1:` token with Lumina's private key (brain sees plaintext) and **seals her reply** to the operator's published prekey.
- **Send/receive**: on send, if the recipient advertises a prekey the body is sealed hybrid; else the classical path is used **unchanged** (control sentinels `__…` are never sealed). On receive, a `pqdm1:` token is opened with the device private key. The **per-conversation self-report** flips to `hybrid-pq`, surfaced by a 🔐 **PQ** badge in the conversation header.

**The interop gate passed BOTH directions** (the requirement): a Python-`pqdm.py`-sealed blob is opened by the Dart `PqDmCodec`, and a Dart-sealed blob is opened by `pqdm.py` — proven by cross-impl vectors (`skchat-app/test/pqc_vectors/{python_sealed,dart_sealed}.json` + `dart test` + `verify_dart_vector.py`). AAD bytes match `downgrade_lock_aad` exactly; the downgrade-lock fails an open on suite mismatch.

| Surface | Suite | Status |
|---|---|---|
| dm (app ↔ Lumina, hybrid-negotiated, **web**) | `x25519-mlkem768` | **hybrid-pq** |
| dm (classical-only peer / no prekey) | `x25519-pgp-wrap-v1` | classical |
| group-key (hybrid-migrated) | `x25519-mlkem768` | **hybrid-pq** |
| at-rest (hybrid-wrapped store) | `x25519-mlkem768` | **hybrid-pq** |
| identity / envelope-sig | `ed25519-v1` | classical |

**Honest scope — negotiated, web-priority.** Hybrid engages only when both sides advertise a prekey (app published one + Lumina published hers). Classical peers stay byte-for-byte unchanged (negotiated downgrade). The prekey **signature stays classical** (Phase 2 / Q7) — only the KEM is quantum-resistant. **In-browser today:** keygen + seal + open via noble (no native binary needed). **Native-mobile follow-up:** the same `PqDmCodec` runs on liboqs FFI once per-arch liboqs binaries ship — no code change, just the backend. The default `build_report()` stays classical until prekeys are published fleet-wide.

Next milestones: native-mobile liboqs binaries (drop-in for the same codec), fleet prekey publication so the *default* DM line flips hybrid-pq, then Phase 2 (signatures / identity — Q6/Q7).

## 2026-06-24 — Entry #6: Confidentiality CUT-OVER — hybrid is now the DEFAULT for new objects; existing migrated where keys present  🔐🚦

The confidentiality cut-over: hybrid **X25519 + ML-KEM-768** (FIPS 203) is no
longer opt-in — it is the **DEFAULT for NEW objects** fleet-wide, and existing
objects are migrated wherever the keys exist. Nothing is forced; classical peers
and un-keyed objects keep working byte-for-byte.

What changed (defaults flipped):
- **New groups default hybrid.** `GroupChat.create()` now defaults `kem_suite` to
  `x25519-mlkem768` (`DEFAULT_NEW_KEM_SUITE`); the create paths
  (`daemon_proxy_groups.create_group`, MCP `create_group` /
  `skchat_group_create`, CLI `group create` / `quick-start`) collect each
  member's hybrid prekey and seed epoch 1 for the members that have one. A new
  group is hybrid from epoch 1 for keyed members; un-keyed members fall back
  classically and are flagged (never locked out). `--classical` opts out.
  **The serialization FIELD default stays `rsa-pgp-wrap-v1`** so groups written
  before the cut-over still deserialize + report as classical (byte-for-byte).
- **New DMs negotiate hybrid by default.** skcomms `EnvelopeCrypto` gained a
  `hybrid_provider` (the shared `~/.skchat/pqc/` prekey store via
  `skcomms.pq_provider`); `_apply_outbound_crypto` now calls
  `encrypt_payload_provider` → hybrid when the recipient advertises a prekey,
  classical otherwise. Inbound `pqdm1:` payloads route to the hybrid opener.
  (skchat 1:1 DMs + app already negotiated hybrid per Q3/Q5.)
- **New at-rest stores hybrid-wrap by default** (`EncryptedChatHistory.from_identity`
  → random DEK sealed X25519+ML-KEM-768 — already the Q4 default; confirmed).
- **Agents publish prekeys on startup.** `skchat.pq_prekeys` is now agent-aware
  (keyed by `SKAGENT`; lumina keeps her legacy filenames). The daemon publishes
  the resident agent's hybrid prekey on boot (`daemon._init_pqc_prekey`), so DMs
  to it negotiate hybrid by default. capauth's identity layer reports
  hybrid-capability honestly (`capauth.pqc_confidentiality`).

Live migration on the operator's OWN data (backup taken first):
- **Backup:** `~/.skchat-pqc-backup/<ts>/` (groups + pqc keystore + at-rest +
  *.db) — mandatory before any write.
- **Groups:** 422 total → **4 migrated** to hybrid (the operator's `penguins`
  groups: epoch 1, all members keyed, each round-trip verified before persist) ·
  **418 skipped** (member(s) lack a hybrid prekey — left classical, flagged, NOT
  forced) · 0 failed. Idempotent: a re-run migrates nothing new (the 4 read
  already-hybrid).
- **At-rest store:** present (97 msgs), already hybrid-wrapped (`qr=True`); the
  re-wrap is a verified no-op.

| Surface | Suite | Status |
|---|---|---|
| group-key (migrated, all members keyed) | `x25519-mlkem768` | **hybrid-pq** (4/422 groups) |
| group-key (un-migrated / member needs key) | `rsa-pgp-wrap-v1` | classical (418/422) |
| dm / envelope (hybrid-negotiated) | `x25519-mlkem768` | **hybrid-pq** |
| dm / envelope (classical-only / downgraded) | `x25519-pgp-wrap-v1` | classical |
| at-rest (operator store) | `x25519-mlkem768` | **hybrid-pq** |
| identity / envelope-sig | `ed25519-v1` | classical (Phase 2) |

**Honest scope.** `sksecurity status` / `pqc-report` now reflect the LIVE fleet
(`build_live_report()`): the group-key surface reads **"hybrid-pq for 4/422
groups"** and only shows `hybrid-pq` for the surface when *all* groups are
hybrid — while any group is classical the surface stays `classical` with the
mixed-state note. NEW groups/DMs/stores are hybrid by default; the 418 classical
groups migrate via `skchat pqc migrate-fleet` once their members publish a
prekey. **What remains classical & why:** (1) groups whose members have no
published hybrid prekey — peers without a hybrid-capable client (the web/native
app or a daemon that publishes one) cannot go hybrid yet; (2) identity +
per-message signatures (Phase 2 — not HNDL, deferrable). No global / end-to-end
post-quantum claim is made.

Next milestones: fleet prekey publication (so the 418 classical groups become
migratable), then Phase 2 (signatures / identity — Q6/Q7).

## 2026-06-24 — Entry #7: Per-project + per-service reporting + a self-growing JSON ledger  📊 *(observability, df239fe1)*

The reporting layer of the #2 cut-over: the aggregate honest self-report now has **per-project**, **per-service**, and **historical-trend** companions, plus a one-command dashboard. No new crypto — this is the *visibility* over what already shipped (Entries #1-6), holding the same honest-claim discipline (FIPS 203/204/205, classical-vs-hybrid per surface, never global/E2E/"quantum-proof").

What shipped:
- **Per-project reports.** `sksecurity/pqc_report.py` gained `build_project_report(project, live=)` + a `--project` filter on `sksecurity pqc-report`, plus thin `pqc-report` subcommands in **skchat / skcomms / capauth** that delegate to the same honesty engine. Each project sees ONLY its owned surfaces (capauth→identity; skcomms→envelope-sig + envelope-payload; skchat→group-key + dm + at-rest; sksecurity→at-rest). A developer in any repo can ask "what's MY project's PQC posture?" The confidentiality surfaces (dm/envelope-payload) reflect the LIVE published default (hybrid-negotiable iff the resident agent advertises a hybrid prekey) — never a per-peer guarantee.
- **SKStacks per-service itemization.** New `sksecurity/pqc_stacks.py` + `sksecurity pqc-stacks` parse the SKStacks v2 descriptors (`apps/*/stack/*.yml`, `overlays/`) and itemize EACH service with its honest posture (transport / at-rest / identity). Today every service transport is **classical TLS** (Traefik ECDHE/RSA/ECDSA — Shor-breakable) or has no crypto surface; **no stack service is quantum-resistant**. Unknown services are flagged **`unaudited`** (explicitly UNKNOWN — never assumed-secure), not `classical`/`n/a`.
- **Self-growing JSON ledger.** `docs/pqc-progression.json` is the machine-readable companion to this narrative .md — seeded with the key facts of Entries #1-6, then **append-only** via `sksecurity pqc-snapshot`, which records a DATED per-surface + per-group snapshot of the live posture. The trend (how many surfaces/groups flipped over time) is now reconstructable from data, not just hand-typed entries.
- **Dashboard.** `sksecurity pqc-dashboard` is one view of the whole ecosystem: aggregate + per-project + per-service + the trend (read from the JSON). One command to see the entire quantum-resistance posture.

### Current posture (unchanged from Entry #6 — this is reporting, not migration)

| Surface | Suite | Status |
|---|---|---|
| identity / envelope-sig | `ed25519-v1` | classical (Phase 2) |
| group-key (migrated, all members keyed) | `x25519-mlkem768` | **hybrid-pq** (live count via snapshot) |
| group-key (un-migrated) | `rsa-pgp-wrap-v1` | classical |
| dm / envelope (hybrid-negotiated) | `x25519-mlkem768` | **hybrid-pq** |
| at-rest (operator store) | `x25519-mlkem768` | **hybrid-pq** |
| SKStacks services (transport) | classical TLS / unaudited | classical · symmetric · n/a · unaudited |

**Honest scope.** The per-project/per-service/dashboard views are *visibility*, not new protection. They cannot mark a surface quantum-resistant unless its live suite already is. SKStacks services are honestly classical/symmetric/n/a with unknowns flagged `unaudited`; PQC has not reached the stack-transport layer (no PQC TLS / hybrid KEX in Traefik). No global / end-to-end / post-quantum claim is made.

Next milestones: fleet prekey publication (so the 418 classical groups become migratable), then Phase 2 (signatures / identity — Q6/Q7). The JSON ledger will record each flip automatically as `pqc-snapshot` runs.
