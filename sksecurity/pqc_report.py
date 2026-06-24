"""Runtime PQC self-report — evidence-backed crypto-posture enumeration.

This is the **honesty engine** for the PQC-MIGRATION epic (Phase 0 / Q0). It
enumerates, per security surface (identity, envelope signature, group key,
at-rest), the cipher-suite id *actually in use today* and its quantum-resistance
status, citing FIPS references. Per §0/§4.4 of
``docs/quantum-resistance-architecture.md``, no external quantum-resistance
claim may be made unless it maps to a line in this report.

**Today it MUST report everything asymmetric as ``classical``** — we have not
migrated any algorithm yet (Q0 is scaffolding only). The report deliberately
has no way to mark a surface quantum-resistant unless the underlying suite in
the registry says so *and* is active.

The single source of truth for suite semantics is
``skcomms.crypto_suites``. If skcomms is importable we read it live; otherwise
we fall back to an embedded snapshot so the report works standalone (sksecurity
does not hard-depend on skcomms).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def _silence_oqs_banner() -> None:
    """Pre-import oqs with stdout muted (it prints a banner to STDOUT, which
    would corrupt this report's ``--format json`` output). Best-effort no-op if
    oqs is absent."""
    import contextlib
    import io as _io
    try:
        with contextlib.redirect_stdout(_io.StringIO()):
            import oqs  # noqa: F401
    except Exception:
        pass


_silence_oqs_banner()


# ---------------------------------------------------------------------------
# Registry access — live skcomms if available, else embedded fallback snapshot.
# ---------------------------------------------------------------------------

# Embedded fallback: suite_id -> (status, fips_refs, primitives). Mirrors the
# CLASSICAL/SYMMETRIC entries of skcomms.crypto_suites so the self-report is
# correct even when skcomms is not installed. Quantum-resistance is derived
# from status, never asserted.
_FALLBACK_SUITES: dict[str, dict] = {
    "ed25519-v1": {
        "status": "classical",
        "primitives": ["Ed25519", "SHA-256"],
        "fips_refs": ["RFC 8032", "RFC 9580"],
    },
    "rsa4096-v1": {
        "status": "classical",
        "primitives": ["RSA-4096", "SHA-256"],
        "fips_refs": ["RFC 8017", "RFC 9580"],
    },
    "rsa-pgp-wrap-v1": {
        "status": "classical",
        "primitives": ["PGP key-wrap (Curve25519/RSA)", "AES-256 session key"],
        "fips_refs": ["RFC 9580"],
    },
    "x25519-pgp-wrap-v1": {
        "status": "classical",
        "primitives": ["X25519 PGP key-wrap", "AES-256 session key"],
        "fips_refs": ["RFC 7748", "RFC 9580"],
    },
    "aes256-gcm-v1": {
        "status": "symmetric",
        "primitives": ["AES-256-GCM", "HKDF-SHA256"],
        "fips_refs": ["FIPS 197", "SP 800-38D", "SP 800-108"],
    },
    # PQC Q2 — LIVE hybrid group-key distribution (skchat group epoch-ratchet).
    "x25519-mlkem768": {
        "status": "hybrid-pq",
        "primitives": [
            "X25519 (ephemeral-static DHKEM)",
            "ML-KEM-768 (FIPS 203, liboqs)",
            "HKDF-SHA256 concat-KDF combiner",
        ],
        "fips_refs": ["FIPS 203", "RFC 7748", "RFC 5869"],
    },
    # PQC Q7 — LIVE hybrid per-message / challenge signature (Ed25519+ML-DSA-65).
    "mldsa65-ed25519-v2": {
        "status": "hybrid-pq",
        "primitives": [
            "Ed25519 (RFC 8032)",
            "ML-DSA-65 (FIPS 204, liboqs)",
            "length-prefixed SKHS composite (both legs required)",
        ],
        "fips_refs": ["FIPS 204", "RFC 8032"],
    },
}

_QR_STATUSES = {"hybrid-pq", "pq", "symmetric"}


def _resolve_suite(suite_id: str) -> dict:
    """Resolve a suite id to {status, primitives, fips_refs, quantum_resistant}.

    Prefers the live ``skcomms.crypto_suites`` registry; falls back to the
    embedded snapshot. Unknown ids resolve as ``classical`` (never reported
    quantum-resistant) for honesty.
    """
    try:  # live registry preferred
        from skcomms.crypto_suites import get_suite  # type: ignore

        suite = get_suite(suite_id)
        if suite is not None:
            d = suite.to_dict()
            return {
                "status": d["status"],
                "primitives": d["primitives"],
                "fips_refs": d["fips_refs"],
                "quantum_resistant": d["quantum_resistant"],
                "active": d["active"],
            }
    except Exception:
        pass

    snap = _FALLBACK_SUITES.get(
        suite_id,
        {"status": "classical", "primitives": ["unknown"], "fips_refs": []},
    )
    return {
        "status": snap["status"],
        "primitives": snap["primitives"],
        "fips_refs": snap["fips_refs"],
        "quantum_resistant": snap["status"] in _QR_STATUSES,
        "active": True,
    }


@dataclass
class SurfaceReport:
    """One security surface's live crypto posture."""

    surface: str               # e.g. "identity", "envelope-sig", "group-key", "at-rest"
    component: str             # owning repo/module
    active_suite: str          # suite id actually in use TODAY
    status: str = ""           # resolved: classical/symmetric/hybrid-pq/pq
    quantum_resistant: bool = False
    primitives: list[str] = field(default_factory=list)
    fips_refs: list[str] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "surface": self.surface,
            "component": self.component,
            "active_suite": self.active_suite,
            "status": self.status,
            "quantum_resistant": self.quantum_resistant,
            "primitives": self.primitives,
            "fips_refs": self.fips_refs,
            "note": self.note,
        }


# The surfaces we own, mapped to the suite id each currently uses. These default
# ids are the classical Q0 defaults baked into the data models:
#   - envelope-sig : SignedEnvelope.sig_suite default   ("ed25519-v1")
#   - group-key    : GroupChat.kem_suite default         ("rsa-pgp-wrap-v1")
#   - identity     : capauth KeyInfo.algorithm default   (ed25519 -> "ed25519-v1")
#   - at-rest      : encrypted_store / KMS               ("aes256-gcm-v1", symmetric)
_DEFAULT_SURFACES: list[tuple[str, str, str, str]] = [
    (
        "identity",
        "capauth (KeyInfo.algorithm)",
        "ed25519-v1",
        "Agent/operator ROOT PGP signing identity — CLASSICAL Ed25519/RSA, "
        "Shor-breakable (HNDL N/A — signatures not retroactive). The ROOT PGP "
        "key is NOT migrated (gated Sequoia decision). A hybrid Ed25519+ML-DSA-65 "
        "(FIPS 204) signature is AVAILABLE opt-in at the DID/challenge LAYER ONLY "
        "via capauth.pqc_identity (respond/verify_challenge_hybrid), using a "
        "per-agent ML-DSA key SEPARATE from the PGP root. Use "
        "challenge_sig_surface_for(response) to report a specific challenge's "
        "real suite.",
    ),
    (
        "envelope-sig",
        "skcomms (SignedEnvelope.sig_suite)",
        "ed25519-v1",
        "Per-message detached signature over canonical_bytes. DEFAULT is "
        "classical Ed25519 (ed25519-v1); a hybrid Ed25519+ML-DSA-65 (FIPS 204) "
        "signature is now AVAILABLE / opt-in per envelope via "
        "skcomms.signing.HybridEnvelopeSigner (sig_suite=mldsa65-ed25519-v2, "
        "either-or verify). Future-forgery risk on the classical default; not "
        "HNDL. Use envelope_sig_surface_for(signed) to report a specific "
        "envelope's real suite. The ROOT PGP identity key is NOT migrated "
        "(Phase-2 Sequoia, gated).",
    ),
    (
        "group-key",
        "skchat (GroupChat.kem_suite)",
        "rsa-pgp-wrap-v1",
        "PGP-wrap of the AES-256 group key. HNDL-EXPOSED — recorded ciphertext "
        "retroactively decryptable. Top Phase-1 priority (Q2).",
    ),
    (
        "at-rest",
        "skchat/sksecurity (AES-256-GCM stores, KMS)",
        "aes256-gcm-v1",
        "Symmetric bulk encryption — Grover-only (~128-bit), quantum-acceptable. "
        "The DEK key-WRAP layer (not the bulk cipher) can now be sealed with the "
        "hybrid X25519+ML-KEM-768 KEM (Q4: skchat.atrest_wrap). AVAILABLE / opt-in "
        "per store; the fingerprint-keying bug is fixed (DEK is random, not "
        "fingerprint-derived). Use atrest_surface_for(store) to report a specific "
        "store's real wrap suite.",
    ),
]

#: Suite id for the at-rest symmetric baseline (matches skcomms.crypto_suites).
DEFAULT_AT_REST_SUITE = "aes256-gcm-v1"


def atrest_surface_for(store) -> tuple[str, str, str, str]:
    """Build the ``at-rest`` surface tuple for a LIVE encrypted store (Q4).

    Mirrors :func:`group_surface_for`: reflects a SPECIFIC store's real DEK-wrap
    suite so a hybrid-wrapped store reports ``x25519-mlkem768`` [hybrid-pq] while
    an un-migrated (symmetric-only / legacy-keyed) store still reports the
    classical/symmetric baseline. The report reflects reality per store (PQC §4.4).

    Args:
        store: A ``skchat.encrypted_store.EncryptedChatHistory`` (duck-typed:
            exposes ``crypto_self_report()`` returning ``wrap_suite`` /
            ``quantum_resistant``), or any object with a ``_wrap_suite`` attr.

    Returns:
        ``(surface, component, suite_id, note)`` for :func:`build_report`.
    """
    is_hybrid = False
    try:
        rpt = store.crypto_self_report()
        is_hybrid = bool(rpt.get("quantum_resistant"))
    except Exception:
        suite = getattr(store, "_wrap_suite", None)
        is_hybrid = suite == "x25519-mlkem768"

    if is_hybrid:
        note = (
            "DEK is high-entropy random, sealed with hybrid X25519+ML-KEM-768 "
            "(skchat.atrest_wrap). Bulk AES-256-GCM is Grover-only. HNDL-resistant: "
            "a harvested backup is not retroactively decryptable. Fingerprint-keying "
            "bug fixed."
        )
        suite_id = "x25519-mlkem768"
    else:
        note = (
            "Symmetric AES-256-GCM bulk (quantum-acceptable) but the DEK wrap is "
            "classical/legacy. Migrate via EncryptedChatHistory.migrate_store() to "
            "the hybrid x25519-mlkem768 DEK wrap (Q4)."
        )
        suite_id = DEFAULT_AT_REST_SUITE
    return ("at-rest", "skchat (encrypted_store DEK wrap)", suite_id, note)


def challenge_sig_surface_for(response) -> tuple[str, str, str, str]:
    """Build the ``identity`` surface tuple for a SPECIFIC challenge response.

    Reflects whether a particular capauth ``ChallengeResponse`` carried a hybrid
    Ed25519+ML-DSA-65 signature (``response.is_hybrid``) at the DID/challenge
    LAYER. This NEVER implies the ROOT PGP key migrated — it reports the
    signing-layer suite only, honestly. A classical response reports
    ``ed25519-v1``; a hybrid one reports ``mldsa65-ed25519-v2`` [hybrid-pq].
    """
    is_hybrid = bool(getattr(response, "is_hybrid", False))
    if is_hybrid:
        suite_id = "mldsa65-ed25519-v2"
        note = (
            "Challenge response carried a hybrid Ed25519 + ML-DSA-65 (FIPS 204) "
            "signature ALONGSIDE the classical PGP signature (either-or verify). "
            "This is the DID/challenge signing layer ONLY — the ROOT PGP identity "
            "key is unchanged (Phase-2 Sequoia, gated)."
        )
    else:
        suite_id = getattr(response, "sig_suite", "ed25519-v1")
        note = (
            "Classical PGP challenge signature (Shor-breakable). Hybrid is "
            "available opt-in via capauth.pqc_identity; the ROOT PGP key is not "
            "migrated."
        )
    return ("identity", "capauth (challenge sig layer)", suite_id, note)


def envelope_sig_surface_for(signed) -> tuple[str, str, str, str]:
    """Build the ``envelope-sig`` surface tuple for a SPECIFIC signed envelope.

    Mirrors :func:`group_surface_for`: reflects a particular
    ``skcomms.envelope.SignedEnvelope``'s real ``sig_suite`` so a hybrid-signed
    envelope reports ``mldsa65-ed25519-v2`` [hybrid-pq] while a classical
    PGP/Ed25519 envelope reports ``ed25519-v1`` [classical]. The report reflects
    reality per envelope (PQC §4.4) and never overclaims.

    Args:
        signed: A ``skcomms.envelope.SignedEnvelope`` (duck-typed: exposes
            ``sig_suite`` and ``is_hybrid``).

    Returns:
        ``(surface, component, suite_id, note)`` for :func:`build_report`.
    """
    is_hybrid = bool(getattr(signed, "is_hybrid", False))
    if is_hybrid:
        suite_id = "mldsa65-ed25519-v2"
        note = (
            "Envelope signed with the hybrid Ed25519 + ML-DSA-65 composite "
            "(FIPS 204): valid iff BOTH legs verify; unforgeable while EITHER "
            "scheme holds. The ML-DSA signer key is per-signer and SEPARATE from "
            "the PGP root (which is NOT migrated — Phase-2 Sequoia, gated)."
        )
    else:
        suite_id = getattr(signed, "sig_suite", "ed25519-v1")
        note = (
            "Classical Ed25519/PGP detached signature (Shor-breakable, "
            "future-forgery; not HNDL). A hybrid Ed25519+ML-DSA-65 signature is "
            "available opt-in via skcomms.signing.HybridEnvelopeSigner."
        )
    return ("envelope-sig", "skcomms (SignedEnvelope.sig_suite)", suite_id, note)


def group_surface_for(group) -> tuple[str, str, str, str]:
    """Build the ``group-key`` surface tuple for a LIVE ``GroupChat``.

    The default :func:`build_report` describes the *default* (classical) group
    suite for honesty. This helper instead reflects a SPECIFIC group's real
    ``kem_suite`` so a hybrid-ratchet group's group-key surface reports
    ``x25519-mlkem768`` [hybrid-pq] while a classical group still reports
    classical — the report reflects reality per group (PQC §4.4).

    Pass the result into ``build_report(surfaces=[...])`` (alongside the other
    default surfaces if a full report is wanted) or read ``group.crypto_self_report()``
    directly for the group-scoped view.

    Args:
        group: A ``skchat.group.GroupChat`` (duck-typed: needs ``id``,
            ``kem_suite``, ``epoch``, and ``is_hybrid``).

    Returns:
        ``(surface, component, suite_id, note)`` for :func:`build_report`.
    """
    suite_id = getattr(group, "kem_suite", DEFAULT_GROUP_NOTE_SUITE)
    if getattr(group, "is_hybrid", False):
        note = (
            f"Group {getattr(group, 'id', '?')[:8]} on the hybrid epoch-ratchet "
            f"(epoch {getattr(group, 'epoch', 0)}). Per-epoch secret wrapped via "
            "X25519+ML-KEM-768; per-message keys derive symmetrically (AES-256-GCM "
            "bulk). HNDL-resistant for this group."
        )
    else:
        note = (
            "Classical PGP-wrap of a static AES-256 group key (HNDL-exposed). "
            "Migrate via GroupChat.migrate_to_hybrid() to reach x25519-mlkem768."
        )
    return ("group-key", "skchat (GroupChat.kem_suite)", suite_id, note)


#: Classical fallback suite for a DM/envelope conversation with no hybrid prekey.
DEFAULT_CONVERSATION_SUITE = "x25519-pgp-wrap-v1"


def conversation_surface_for(
    negotiated_suite: str,
    kind: str = "dm",
    peer: str = "",
) -> tuple[str, str, str, str]:
    """Build a per-conversation DM/envelope surface tuple (PQC Q3 — REALITY).

    Mirrors :func:`group_surface_for` for the 1:1 / envelope confidentiality
    surfaces (plan §3 S4/S6). The default :func:`build_report` describes the
    *default* (classical) DM/envelope suite for honesty; this helper instead
    reflects a SPECIFIC conversation's actually-negotiated ``kem_suite`` so a
    hybrid conversation reports ``x25519-mlkem768`` [hybrid-pq] while a classical
    (downgraded / classical-only-peer) conversation still reports classical.

    The negotiated suite comes from
    ``EnvelopeCrypto.negotiated_suite`` / ``ChatCrypto.negotiated_suite`` (or the
    ``kem_suite`` recorded on a sealed message's metadata) — never hard-coded, so
    a silent-downgrade attempt shows up here as a classical line rather than a
    hybrid one.

    Args:
        negotiated_suite: The suite the conversation actually used
            (``x25519-mlkem768`` for hybrid, else the classical wrap).
        kind: ``"dm"`` (skchat 1:1) or ``"envelope"`` (skcomms payload).
        peer: Optional peer identifier for the note.

    Returns:
        ``(surface, component, suite_id, note)`` for :func:`build_report`.
    """
    suite_id = negotiated_suite or DEFAULT_CONVERSATION_SUITE
    if kind == "envelope":
        surface = "envelope-payload"
        component = "skcomms (EnvelopeCrypto)"
    else:
        surface = "dm"
        component = "skchat (ChatCrypto)"
    resolved = _resolve_suite(suite_id)
    who = f" with {peer}" if peer else ""
    if resolved["quantum_resistant"]:
        note = (
            f"{surface.upper()} conversation{who} negotiated the hybrid KEM: the "
            "body symmetric key is wrapped via X25519+ML-KEM-768 (PQXDH-style "
            "signed prekey) and AES-256-GCM seals the body. Negotiated suite is "
            "bound into the AEAD AAD (downgrade-lock). HNDL-resistant."
        )
    else:
        note = (
            f"{surface.upper()} conversation{who} on the CLASSICAL PGP key-wrap "
            "(HNDL-exposed). Either the peer advertised no hybrid prekey or a "
            "downgrade occurred — recorded honestly. Hybrid engages only when "
            "both sides advertise a hybrid prekey."
        )
    return (surface, component, suite_id, note)


#: Suite id used when a group object omits ``kem_suite`` (defensive default).
DEFAULT_GROUP_NOTE_SUITE = "rsa-pgp-wrap-v1"


def build_report(surfaces: Optional[list[tuple[str, str, str, str]]] = None) -> dict:
    """Build the full PQC self-report.

    Args:
        surfaces: Optional override list of ``(surface, component, suite_id,
            note)`` tuples. Defaults to the owned surfaces.

    Returns:
        dict with ``surfaces`` (list of per-surface dicts), ``summary`` counts,
        a ``registry_source`` marker, and an ``honest_claim`` string. By design
        the summary shows all-classical/symmetric (no quantum-resistant
        asymmetric surface) until Phase 1 migrates a suite.
    """
    surfaces = surfaces or _DEFAULT_SURFACES

    # Detect whether the live registry was reachable (affects source marker).
    registry_source = "embedded-fallback"
    try:
        import skcomms.crypto_suites  # noqa: F401

        registry_source = "skcomms.crypto_suites (live)"
    except Exception:
        pass

    reports: list[SurfaceReport] = []
    for surface, component, suite_id, note in surfaces:
        resolved = _resolve_suite(suite_id)
        reports.append(
            SurfaceReport(
                surface=surface,
                component=component,
                active_suite=suite_id,
                status=resolved["status"],
                quantum_resistant=resolved["quantum_resistant"],
                primitives=resolved["primitives"],
                fips_refs=resolved["fips_refs"],
                note=note,
            )
        )

    total = len(reports)
    qr = sum(1 for r in reports if r.quantum_resistant)
    classical = sum(1 for r in reports if r.status == "classical")
    symmetric = sum(1 for r in reports if r.status == "symmetric")

    if qr == total:
        honest_claim = "All owned surfaces are quantum-resistant."
    elif any(r.status == "classical" for r in reports):
        honest_claim = (
            "NOT quantum-resistant end-to-end. All asymmetric surfaces are "
            "CLASSICAL (Shor-breakable). Symmetric/at-rest layers are "
            "quantum-acceptable. PQC migration has not started (Q0 scaffolding "
            "only). Do not claim hybrid/post-quantum protection."
        )
    else:
        honest_claim = (
            "Only symmetric surfaces present; no asymmetric PQ migration done."
        )

    return {
        "report": "pqc-self-report",
        "phase": "Q0 (crypto-agility scaffolding — no algorithm migrated yet)",
        "registry_source": registry_source,
        "surfaces": [r.to_dict() for r in reports],
        "summary": {
            "total_surfaces": total,
            "quantum_resistant": qr,
            "classical": classical,
            "symmetric": symmetric,
        },
        "honest_claim": honest_claim,
    }


# ---------------------------------------------------------------------------
# Live, reality-reflecting report (PQC confidentiality cut-over).
# ---------------------------------------------------------------------------


def _iter_live_groups():
    """Yield the operator's live ``GroupChat`` objects (best-effort, may be empty).

    Reads ``~/.skchat/groups/*.json`` through skchat's own loader so the report
    reflects REALITY (each group's actual ``kem_suite``), never a hard-coded
    assumption. Returns an empty list if skchat is unavailable.
    """
    try:
        from skchat.daemon_proxy_groups import list_groups  # type: ignore

        return list_groups()
    except Exception:
        return []


def _live_group_summary() -> dict:
    """Counts of hybrid-pq vs classical among the operator's live groups."""
    groups = _iter_live_groups()
    total = len(groups)
    hybrid = sum(1 for g in groups if getattr(g, "is_hybrid", False))
    return {"total": total, "hybrid": hybrid, "classical": total - hybrid}


def _live_store_surface() -> Optional[tuple[str, str, str, str]]:
    """The operator's at-rest store surface, reflecting its real wrap suite.

    Returns ``None`` if no encrypted store exists (so the report falls back to
    the symmetric baseline line rather than inventing a store).
    """
    try:
        from skchat.encrypted_store import EncryptedChatHistory  # type: ignore

        store = EncryptedChatHistory.from_identity()
        return atrest_surface_for(store)
    except Exception:
        return None


def build_live_report() -> dict:
    """Build the PQC self-report from the operator's LIVE objects (cut-over).

    Unlike :func:`build_report` (which describes the *default* posture for
    honesty), this enumerates the operator's actual groups and at-rest store and
    reports the real mixed state:

    * **group-key** surface reflects how many of N groups are hybrid-pq. The
      surface is marked ``hybrid-pq`` ONLY when *every* group is hybrid; while
      any group is still classical the surface stays ``classical`` with a
      ``hybrid-pq for X/N groups`` note — never an overclaim.
    * **at-rest** reflects the real DEK-wrap suite of the live store (or the
      symmetric baseline when no store exists).
    * identity / envelope-sig stay classical (Phase 2, unchanged).

    Adds ``group_breakdown`` counts so callers can render
    "group-key: hybrid-pq for N/M groups".
    """
    gsum = _live_group_summary()
    surfaces: list[tuple[str, str, str, str]] = []

    # identity + envelope-sig: unchanged classical defaults (Phase 2).
    surfaces.append(_DEFAULT_SURFACES[0])  # identity
    surfaces.append(_DEFAULT_SURFACES[1])  # envelope-sig

    # group-key: reflect the real fleet ratio.
    if gsum["total"] == 0:
        # No groups yet — describe the NEW-object default honestly (hybrid).
        surfaces.append((
            "group-key",
            "skchat (GroupChat.kem_suite)",
            "x25519-mlkem768",
            "No groups exist yet. NEW groups default to hybrid x25519-mlkem768 "
            "(PQC cut-over); the surface will report hybrid-pq once groups exist "
            "and are all hybrid.",
        ))
    elif gsum["hybrid"] == gsum["total"]:
        surfaces.append((
            "group-key",
            "skchat (GroupChat.kem_suite)",
            "x25519-mlkem768",
            f"All {gsum['total']} group(s) on the hybrid epoch-ratchet "
            "(x25519-mlkem768). HNDL-resistant fleet-wide.",
        ))
    else:
        surfaces.append((
            "group-key",
            "skchat (GroupChat.kem_suite)",
            "rsa-pgp-wrap-v1",
            f"MIXED: hybrid-pq for {gsum['hybrid']}/{gsum['total']} group(s); "
            f"{gsum['classical']} still classical (needs hybrid key / not "
            "migrated). NEW groups default hybrid; migrate the rest via "
            "`skchat pqc migrate-fleet` once members publish prekeys.",
        ))

    # at-rest: real store or symmetric baseline.
    store_surface = _live_store_surface()
    surfaces.append(store_surface if store_surface is not None else _DEFAULT_SURFACES[3])

    report = build_report(surfaces=surfaces)
    report["phase"] = (
        "Confidentiality cut-over — hybrid is the DEFAULT for new objects; "
        "existing objects migrated where keys are present"
    )
    report["group_breakdown"] = gsum

    # Honest claim for the cut-over reality (the default build_report claim
    # assumes Q0/no-migration, which is now false). State exactly what is true:
    # confidentiality (KEM/at-rest) is hybrid where migrated; identity/signatures
    # stay classical (Phase 2). Never claim global hybrid.
    qr_surfaces = [s for s in report["surfaces"] if s["quantum_resistant"]]
    g_hybrid = gsum["hybrid"]
    g_total = gsum["total"]
    parts = [
        "Confidentiality cut-over IN PROGRESS (honest mixed state). "
        "Hybrid X25519+ML-KEM-768 (FIPS 203) is the DEFAULT for NEW groups, "
        "DMs (negotiated when both peers advertise a prekey), and at-rest DEK "
        "wrapping."
    ]
    if g_total:
        parts.append(
            f"group-key: hybrid-pq for {g_hybrid}/{g_total} existing groups "
            f"({gsum['classical']} still classical — members need a hybrid prekey "
            "or have not migrated)."
        )
    parts.append(
        "Identity + per-message signatures remain CLASSICAL (Shor-breakable, "
        "Phase 2 — not HNDL). NOT quantum-resistant end-to-end; never assert "
        "global, end-to-end, or unconditional post-quantum protection."
    )
    report["honest_claim"] = " ".join(parts)
    return report


def format_report(report: Optional[dict] = None) -> str:
    """Render the PQC self-report as human-readable text."""
    rpt = report or build_report()
    lines = []
    lines.append("🔐 PQC Self-Report (per-surface crypto posture)")
    lines.append("=" * 52)
    lines.append(f"Phase:    {rpt['phase']}")
    lines.append(f"Registry: {rpt['registry_source']}")
    lines.append("")
    for s in rpt["surfaces"]:
        flag = "✅ quantum-resistant" if s["quantum_resistant"] else "⚠️  classical"
        if s["status"] == "symmetric":
            flag = "✅ symmetric (quantum-acceptable)"
        lines.append(f"• {s['surface']:<13} [{s['status']}] {flag}")
        lines.append(f"    component : {s['component']}")
        lines.append(f"    suite     : {s['active_suite']}")
        lines.append(f"    primitives: {', '.join(s['primitives'])}")
        if s["fips_refs"]:
            lines.append(f"    refs      : {', '.join(s['fips_refs'])}")
        if s["note"]:
            lines.append(f"    note      : {s['note']}")
        lines.append("")
    sm = rpt["summary"]
    lines.append(
        f"Summary: {sm['quantum_resistant']}/{sm['total_surfaces']} "
        f"quantum-resistant  ·  {sm['classical']} classical  ·  "
        f"{sm['symmetric']} symmetric"
    )
    gb = rpt.get("group_breakdown")
    if gb is not None:
        if gb["total"] == 0:
            lines.append("group-key: no groups yet — new groups default hybrid-pq")
        else:
            lines.append(
                f"group-key: hybrid-pq for {gb['hybrid']}/{gb['total']} groups "
                f"({gb['classical']} classical)"
            )
    lines.append("")
    lines.append(f"Honest claim: {rpt['honest_claim']}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Per-project reports (df239fe1) — a developer in any repo can ask "what is MY
# project's PQC posture?" Each project owns a subset of the surfaces. We reuse
# the SAME resolution + honesty logic (build_report / build_live_report) and
# simply filter to the surfaces a given project owns. Nothing here can mark a
# surface quantum-resistant unless the underlying live suite says so.
# ---------------------------------------------------------------------------

#: project -> the set of surface names that project OWNS (is the source of truth
#: for). Sourced from the SurfaceReport.component ownership already encoded in
#: _DEFAULT_SURFACES + the live surfaces (dm/envelope-payload). A surface can be
#: co-owned (at-rest is skchat+sksecurity); we list it under each owner.
PROJECT_SURFACES: dict[str, set[str]] = {
    # capauth owns the agent/operator signing identity (KeyInfo.algorithm).
    "capauth": {"identity"},
    # skcomms owns the per-message envelope signature + envelope payload KEM.
    "skcomms": {"envelope-sig", "envelope-payload"},
    # skchat owns group-key, 1:1 DM confidentiality, and the at-rest chat store.
    "skchat": {"group-key", "dm", "at-rest"},
    # sksecurity owns the aggregate report + the at-rest KMS/store layer.
    "sksecurity": {"at-rest"},
}

#: Human label per project (for headers / honest-claim phrasing).
PROJECT_LABEL = {
    "capauth": "capauth (identity / PGP-SSO)",
    "skcomms": "skcomms (federated envelope transport)",
    "skchat": "skchat (chat / groups / DMs / at-rest store)",
    "sksecurity": "sksecurity (security tooling / KMS / at-rest)",
}


def known_projects() -> list[str]:
    """Return the projects that can emit their own PQC posture report."""
    return sorted(PROJECT_SURFACES)


def _project_honest_claim(project: str, surfaces: list[dict]) -> str:
    """Project-scoped honest claim — never global, never E2E, cites the split."""
    total = len(surfaces)
    qr = [s for s in surfaces if s["quantum_resistant"]]
    classical = [s for s in surfaces if s["status"] == "classical"]
    label = PROJECT_LABEL.get(project, project)
    head = f"{label}: {len(qr)}/{total} owned surface(s) quantum-resistant."
    if not classical:
        if any(s["status"] == "symmetric" for s in surfaces) and not any(
            s["status"] in ("hybrid-pq", "pq") for s in surfaces
        ):
            return (
                head
                + " Only symmetric/at-rest surfaces here (AES-256/SHA-2 — "
                "quantum-acceptable, Grover-only); no asymmetric surface to "
                "migrate. Not an end-to-end quantum-resistance claim."
            )
        return (
            head
            + " Owned asymmetric confidentiality surfaces are on the hybrid "
            "X25519+ML-KEM-768 KEM (FIPS 203) where migrated/negotiated. This "
            "is a per-surface claim for THIS project only — NOT global, NOT "
            "end-to-end, NOT a signature/identity claim."
        )
    classical_names = ", ".join(s["surface"] for s in classical)
    return (
        head
        + f" CLASSICAL (Shor-breakable) surface(s): {classical_names}. "
        "Confidentiality surfaces use hybrid X25519+ML-KEM-768 (FIPS 203) only "
        "where migrated/negotiated; signatures/identity stay classical "
        "(Phase 2). NOT quantum-resistant end-to-end; never claim global or "
        "unconditional post-quantum protection."
    )


def _local_agent_has_hybrid_prekey() -> bool:
    """Best-effort: does the resident agent advertise a hybrid prekey?

    If so, NEW DMs/envelopes default to hybrid-negotiation (cut-over). We read
    the shared prekey store (``~/.skchat/pqc/<agent>_hybrid.pub``) directly so
    the report reflects the real published default without importing skchat.
    Returns False on any uncertainty (never overclaims hybrid).
    """
    try:
        agent = os.environ.get("SKAGENT") or os.environ.get(
            "SKCAPSTONE_AGENT") or os.environ.get("SKMEMORY_AGENT") or "lumina"
        pub = Path.home() / ".skchat" / "pqc" / f"{agent}_hybrid.pub"
        return pub.exists()
    except Exception:
        return False


def live_conversation_surface(kind: str) -> tuple[str, str, str, str]:
    """Default-negotiated DM (``kind='dm'``) / envelope-payload
    (``kind='envelope'``) surface, reflecting the LIVE published default.

    Post cut-over a NEW conversation negotiates hybrid IFF the resident agent
    advertises a hybrid prekey (and the peer does too). We report the local
    DEFAULT honestly: hybrid-negotiable when our prekey is published, classical
    otherwise. Per-conversation reality still comes from
    :func:`conversation_surface_for` with the actually-negotiated suite — this
    is the project-level default view, never a per-peer guarantee.
    """
    if _local_agent_has_hybrid_prekey():
        suite = "x25519-mlkem768"
    else:
        suite = DEFAULT_CONVERSATION_SUITE  # classical fallback
    surface, component, suite_id, note = conversation_surface_for(suite, kind=kind)
    # Make the note explicit that this is the DEFAULT, not a per-peer guarantee.
    if suite == "x25519-mlkem768":
        note = (
            f"{surface.upper()} DEFAULT: the resident agent publishes a hybrid "
            "prekey, so NEW conversations negotiate X25519+ML-KEM-768 (FIPS 203) "
            "when the peer also advertises one; classical-only peers stay "
            "classical (negotiated downgrade, recorded honestly). Not a per-peer "
            "guarantee — see per-conversation self-report."
        )
    else:
        note = (
            f"{surface.upper()} DEFAULT: no hybrid prekey published by the "
            "resident agent → new conversations are CLASSICAL PGP-wrap "
            "(HNDL-exposed). Publish a hybrid prekey to negotiate hybrid."
        )
    return (surface, component, suite_id, note)


def build_project_report(project: str, *, live: bool = True) -> dict:
    """Build the PQC self-report SCOPED to a single project's owned surfaces.

    Reuses :func:`build_live_report` (or :func:`build_report` when ``live`` is
    False) and filters to the surfaces ``project`` owns (:data:`PROJECT_SURFACES`).
    The per-surface resolution + honesty discipline is identical to the aggregate
    report — a surface is only ``quantum-resistant`` when its live suite is.

    Args:
        project: One of :func:`known_projects`.
        live: Reflect the operator's real objects (default) vs the model default.

    Returns:
        A report dict shaped like :func:`build_report` plus ``project`` and a
        project-scoped ``honest_claim``. ``surfaces`` contains ONLY the project's
        surfaces; ``summary`` counts that subset.
    """
    project = project.lower()
    if project not in PROJECT_SURFACES:
        raise ValueError(
            f"unknown project {project!r}; known: {', '.join(known_projects())}"
        )
    owned = PROJECT_SURFACES[project]
    base = build_live_report() if live else build_report()
    surfaces = [s for s in base["surfaces"] if s["surface"] in owned]

    # Add the project's CONFIDENTIALITY surface (dm / envelope-payload), which the
    # aggregate report does not enumerate by default. Reflect the live published
    # default (hybrid-negotiable vs classical) so a developer sees the real
    # confidentiality posture their project ships, not just signatures.
    if live:
        if "dm" in owned:
            tup = live_conversation_surface("dm")
            resolved = _resolve_suite(tup[2])
            surfaces.append(SurfaceReport(
                surface=tup[0], component=tup[1], active_suite=tup[2],
                status=resolved["status"],
                quantum_resistant=resolved["quantum_resistant"],
                primitives=resolved["primitives"], fips_refs=resolved["fips_refs"],
                note=tup[3]).to_dict())
        if "envelope-payload" in owned:
            tup = live_conversation_surface("envelope")
            resolved = _resolve_suite(tup[2])
            surfaces.append(SurfaceReport(
                surface=tup[0], component=tup[1], active_suite=tup[2],
                status=resolved["status"],
                quantum_resistant=resolved["quantum_resistant"],
                primitives=resolved["primitives"], fips_refs=resolved["fips_refs"],
                note=tup[3]).to_dict())

    total = len(surfaces)
    qr = sum(1 for s in surfaces if s["quantum_resistant"])
    classical = sum(1 for s in surfaces if s["status"] == "classical")
    symmetric = sum(1 for s in surfaces if s["status"] == "symmetric")

    out = {
        "report": "pqc-self-report",
        "project": project,
        "project_label": PROJECT_LABEL.get(project, project),
        "phase": base["phase"],
        "registry_source": base["registry_source"],
        "surfaces": surfaces,
        "summary": {
            "total_surfaces": total,
            "quantum_resistant": qr,
            "classical": classical,
            "symmetric": symmetric,
        },
        "honest_claim": _project_honest_claim(project, surfaces),
    }
    # Carry the group breakdown only for the project that owns group-key.
    if "group-key" in owned and "group_breakdown" in base:
        out["group_breakdown"] = base["group_breakdown"]
    return out


def format_project_report(report: dict) -> str:
    """Render a project-scoped report (reuses the surface renderer)."""
    lines = [
        f"🔐 PQC Self-Report — {report.get('project_label', report.get('project'))}",
        "=" * 60,
        f"Project:  {report.get('project')}",
        f"Phase:    {report['phase']}",
        f"Registry: {report['registry_source']}",
        "",
    ]
    # Reuse format_report's per-surface body by delegating on a shallow copy that
    # lacks the project header (format_report re-prints its own header, so we
    # instead inline the surface loop here to avoid a duplicate banner).
    for s in report["surfaces"]:
        flag = "✅ quantum-resistant" if s["quantum_resistant"] else "⚠️  classical"
        if s["status"] == "symmetric":
            flag = "✅ symmetric (quantum-acceptable)"
        lines.append(f"• {s['surface']:<15} [{s['status']}] {flag}")
        lines.append(f"    component : {s['component']}")
        lines.append(f"    suite     : {s['active_suite']}")
        lines.append(f"    primitives: {', '.join(s['primitives'])}")
        if s["fips_refs"]:
            lines.append(f"    refs      : {', '.join(s['fips_refs'])}")
        if s["note"]:
            lines.append(f"    note      : {s['note']}")
        lines.append("")
    sm = report["summary"]
    lines.append(
        f"Summary: {sm['quantum_resistant']}/{sm['total_surfaces']} "
        f"quantum-resistant  ·  {sm['classical']} classical  ·  "
        f"{sm['symmetric']} symmetric"
    )
    gb = report.get("group_breakdown")
    if gb and gb["total"]:
        lines.append(
            f"group-key: hybrid-pq for {gb['hybrid']}/{gb['total']} groups "
            f"({gb['classical']} classical)"
        )
    lines.append("")
    lines.append(f"Honest claim: {report['honest_claim']}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Historical progression ledger — machine-readable companion (df239fe1).
# The human .md (docs/pqc-progression.md) stays the NARRATIVE; this JSON is the
# DATA: a dated, append-only series of live-posture snapshots so we accrue an
# automatic current-vs-enabled history, not just hand-typed entries.
# ---------------------------------------------------------------------------

#: Location of the machine-readable ledger (next to the narrative .md).
LEDGER_JSON = Path(__file__).resolve().parent.parent / "docs" / "pqc-progression.json"


def _snapshot_from_report(rpt: dict) -> dict:
    """Distil a live report into the per-surface + per-group counts we ledger."""
    by_status: dict[str, int] = {}
    for s in rpt["surfaces"]:
        by_status[s["status"]] = by_status.get(s["status"], 0) + 1
    snap = {
        "phase": rpt.get("phase", ""),
        "registry_source": rpt.get("registry_source", ""),
        "summary": rpt.get("summary", {}),
        "status_counts": by_status,
        "surfaces": [
            {
                "surface": s["surface"],
                "active_suite": s["active_suite"],
                "status": s["status"],
                "quantum_resistant": s["quantum_resistant"],
            }
            for s in rpt["surfaces"]
        ],
    }
    gb = rpt.get("group_breakdown")
    if gb is not None:
        snap["group_breakdown"] = gb
    return snap


def load_ledger() -> dict:
    """Load the JSON ledger (or an empty skeleton if it does not exist yet)."""
    if LEDGER_JSON.exists():
        try:
            return json.loads(LEDGER_JSON.read_text())
        except Exception:
            pass
    return {
        "ledger": "pqc-progression",
        "epic": "PQC-MIGRATION (coord e1d6ba2a)",
        "note": (
            "Machine-readable companion to docs/pqc-progression.md. Append-only "
            "dated snapshots of the LIVE posture (sksecurity pqc-snapshot). The "
            ".md is the narrative; this is the data."
        ),
        "legend": {
            "classical": "Shor-breakable (vulnerable)",
            "symmetric": "AES-256/SHA-2 (quantum-acceptable, Grover-only)",
            "hybrid-pq": "X25519+ML-KEM-768 (FIPS 203, target)",
            "pq": "pure post-quantum",
        },
        "snapshots": [],
    }


def save_ledger(ledger: dict) -> None:
    """Write the JSON ledger back to disk (pretty-printed, trailing newline)."""
    LEDGER_JSON.parent.mkdir(parents=True, exist_ok=True)
    LEDGER_JSON.write_text(json.dumps(ledger, indent=2) + "\n")


def append_snapshot(
    *, label: str = "", live: bool = True, when: Optional[str] = None
) -> dict:
    """Append a DATED snapshot of the current live posture to the JSON ledger.

    This is what makes the historical record self-growing: each invocation
    records the real per-surface + per-group state at that moment, so the trend
    (how many surfaces/groups flipped over time) is reconstructable from data —
    not just the hand-appended .md entries.

    Args:
        label: Optional human label for the snapshot (e.g. "Q4 at-rest landed").
        live: Snapshot the live fleet posture (default) vs the model default.
        when: Optional ISO timestamp override (else now, UTC).

    Returns:
        The snapshot dict that was appended.
    """
    rpt = build_live_report() if live else build_report()
    snap = _snapshot_from_report(rpt)
    snap["date"] = when or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    snap["timestamp"] = when or datetime.now(timezone.utc).isoformat()
    if label:
        snap["label"] = label
    snap["kind"] = "live" if live else "default"

    ledger = load_ledger()
    ledger.setdefault("snapshots", []).append(snap)
    save_ledger(ledger)
    return snap


#: Seed entries (the key facts of docs/pqc-progression.md #1-6) so the JSON
#: ledger starts with the same baseline → cut-over history the .md narrates.
#: These are the recorded HISTORY (status_counts only); live snapshots accrue on
#: top via append_snapshot. Kept here so seeding is reproducible/idempotent.
SEED_SNAPSHOTS: list[dict] = [
    {
        "date": "2026-06-23",
        "kind": "milestone",
        "entry": 1,
        "label": "PRE-PQC BASELINE (Q0 — crypto-agility scaffolding, no migration)",
        "surfaces": [
            {"surface": "identity", "active_suite": "ed25519-v1", "status": "classical"},
            {"surface": "envelope-sig", "active_suite": "ed25519-v1", "status": "classical"},
            {"surface": "group-key", "active_suite": "rsa-pgp-wrap-v1", "status": "classical"},
            {"surface": "at-rest", "active_suite": "aes256-gcm-v1", "status": "symmetric"},
        ],
        "status_counts": {"classical": 3, "symmetric": 1},
        "summary": {"total_surfaces": 4, "quantum_resistant": 1, "classical": 3, "symmetric": 1},
    },
    {
        "date": "2026-06-24",
        "kind": "milestone",
        "entry": 2,
        "label": "Q2 group-key → hybrid epoch-ratchet AVAILABLE (per-group / opt-in)",
        "note": "Hybrid ratchet live per-group (kem_suite==x25519-mlkem768); default surface stays classical until groups migrate.",
        "status_counts": {"classical": 3, "symmetric": 1, "hybrid-pq-available": 1},
    },
    {
        "date": "2026-06-24",
        "kind": "milestone",
        "entry": 3,
        "label": "Q3 DM/envelope → hybrid KEM AVAILABLE (per-conversation / negotiated)",
        "note": "pqdm.py shared sealing primitive; hybrid engages only when both peers advertise a prekey; downgrade-locked via AAD.",
        "status_counts": {"classical": 3, "symmetric": 1, "hybrid-pq-available": 2},
    },
    {
        "date": "2026-06-24",
        "kind": "milestone",
        "entry": 4,
        "label": "Q4 at-rest → hybrid key-wrap AVAILABLE + fingerprint-keying bug FIXED",
        "note": "Random DEK sealed X25519+ML-KEM-768; legacy fingerprint-derived DEK retired; Phase-1 HNDL surfaces all have a hybrid path.",
        "status_counts": {"classical": 2, "symmetric": 1, "hybrid-pq-available": 3},
    },
    {
        "date": "2026-06-24",
        "kind": "milestone",
        "entry": 5,
        "label": "Q5 app-side hybrid PQC LIVE — DMs go hybrid in the BROWSER",
        "note": "Flutter PqDmCodec + noble web ML-KEM-768; app↔Lumina DMs negotiate hybrid in-page; interop gate passed both directions.",
        "status_counts": {"classical": 2, "symmetric": 1, "hybrid-pq-available": 3},
    },
    {
        "date": "2026-06-24",
        "kind": "milestone",
        "entry": 6,
        "label": "Confidentiality CUT-OVER — hybrid is the DEFAULT for new objects",
        "note": "New groups/DMs/stores default hybrid; live migration: 4/422 groups hybrid (418 classical — members need prekeys); at-rest store hybrid. identity/sig stay classical (Phase 2).",
        "status_counts": {"classical": 1, "symmetric": 1, "hybrid-pq": 1, "mixed": 1},
        "group_breakdown": {"total": 422, "hybrid": 4, "classical": 418},
    },
    {
        "date": "2026-06-24",
        "kind": "milestone",
        "entry": 8,
        "label": "Q7 per-message + DID/challenge signatures \u2192 hybrid Ed25519+ML-DSA-65 AVAILABLE (opt-in/negotiated)",
        "note": (
            "skcomms.pqsig (FIPS 204 ML-DSA-65 + Ed25519 composite, both legs "
            "required) wired opt-in into SignedEnvelope.sig_suite "
            "(HybridEnvelopeSigner) + capauth.pqc_identity challenge "
            "(respond/verify_challenge_hybrid). Either-or verify; classical "
            "ed25519-v1 stays default for old peers (byte-for-byte unchanged). "
            "ML-DSA signer key is per-signer, SEPARATE from the PGP root. "
            "IDENTITY ROOT PGP key still CLASSICAL \u2014 Sequoia migration "
            "gated/separate."
        ),
        "status_counts": {"classical": 1, "symmetric": 1, "hybrid-pq": 1, "hybrid-pq-available": 1, "mixed": 1},
    },
]


def seed_ledger(force: bool = False) -> dict:
    """Seed the JSON ledger with the #1-6 milestone facts (idempotent).

    Only seeds when the ledger has no snapshots (or ``force``). Returns the
    ledger. Live snapshots accrue on top via :func:`append_snapshot`.
    """
    ledger = load_ledger()
    if ledger.get("snapshots") and not force:
        return ledger
    if force:
        # keep any prior live snapshots, drop prior seeds (by 'entry' marker)
        ledger["snapshots"] = [
            s for s in ledger.get("snapshots", []) if "entry" not in s
        ]
    ledger.setdefault("snapshots", [])
    # prepend seeds in entry order
    ledger["snapshots"] = list(SEED_SNAPSHOTS) + [
        s for s in ledger["snapshots"] if "entry" not in s
    ]
    save_ledger(ledger)
    return ledger


# ---------------------------------------------------------------------------
# PQC dashboard — one view: aggregate + per-project + per-service + trend.
# ---------------------------------------------------------------------------


def build_dashboard(*, live: bool = True, include_stacks: bool = True) -> dict:
    """Assemble the whole-ecosystem PQC posture: aggregate, per-project,
    per-service (SKStacks), and the historical trend (from the JSON ledger).

    Args:
        live: Use the live fleet report (default) vs the model default.
        include_stacks: Include the SKStacks per-service itemization (best-effort;
            omitted with a marker if the stacks repo / descriptors aren't found).

    Returns:
        A dict with ``aggregate``, ``projects`` (name -> scoped report),
        ``stacks`` (per-service, or an ``unavailable`` marker), and ``trend``
        (derived from the ledger snapshots).
    """
    aggregate = build_live_report() if live else build_report()
    projects = {p: build_project_report(p, live=live) for p in known_projects()}

    stacks: dict = {}
    if include_stacks:
        try:
            from .pqc_stacks import build_stacks_report

            stacks = build_stacks_report()
        except Exception as exc:  # honest: don't fabricate a stack list
            stacks = {"unavailable": True, "reason": str(exc)}

    # Trend: derive from the ledger snapshots (history of status_counts).
    ledger = load_ledger()
    snaps = ledger.get("snapshots", [])
    trend = []
    for s in snaps:
        trend.append(
            {
                "date": s.get("date"),
                "label": s.get("label", ""),
                "kind": s.get("kind", ""),
                "status_counts": s.get("status_counts", {}),
                "group_breakdown": s.get("group_breakdown"),
            }
        )

    return {
        "report": "pqc-dashboard",
        "generated": datetime.now(timezone.utc).isoformat(),
        "aggregate": aggregate,
        "projects": projects,
        "stacks": stacks,
        "trend": trend,
    }


def format_dashboard(dash: Optional[dict] = None) -> str:
    """Render the whole-ecosystem PQC dashboard as text."""
    d = dash or build_dashboard()
    L = []
    L.append("🔐🌐 SK ECOSYSTEM PQC DASHBOARD")
    L.append("=" * 60)
    L.append(f"generated: {d['generated']}")
    L.append("")

    # --- Aggregate ---
    agg = d["aggregate"]
    sm = agg["summary"]
    L.append("── AGGREGATE (owned surfaces) ──")
    L.append(f"Phase: {agg['phase']}")
    L.append(
        f"  {sm['quantum_resistant']}/{sm['total_surfaces']} quantum-resistant "
        f"· {sm['classical']} classical · {sm['symmetric']} symmetric"
    )
    for s in agg["surfaces"]:
        mark = "✅" if s["quantum_resistant"] else "⚠️ "
        L.append(f"   {mark} {s['surface']:<15} [{s['status']}] {s['active_suite']}")
    gb = agg.get("group_breakdown")
    if gb and gb["total"]:
        L.append(
            f"   group-key: hybrid-pq for {gb['hybrid']}/{gb['total']} groups "
            f"({gb['classical']} classical)"
        )
    L.append("")

    # --- Per-project ---
    L.append("── PER-PROJECT ──")
    for name, rpt in d["projects"].items():
        psm = rpt["summary"]
        L.append(
            f"  {name:<11} {psm['quantum_resistant']}/{psm['total_surfaces']} qr "
            f"· {psm['classical']} classical · {psm['symmetric']} symmetric"
        )
        for s in rpt["surfaces"]:
            mark = "✅" if s["quantum_resistant"] else "⚠️ "
            L.append(f"       {mark} {s['surface']:<15} [{s['status']}] {s['active_suite']}")
    L.append("")

    # --- Per-service (SKStacks) ---
    L.append("── PER-SERVICE (SKStacks) ──")
    st = d.get("stacks") or {}
    if st.get("unavailable"):
        L.append(f"  (unavailable: {st.get('reason', 'no descriptors found')})")
    else:
        for svc in st.get("services", []):
            posture = svc.get("posture", "unaudited")
            mark = {
                "hybrid-pq": "✅",
                "symmetric": "✅",
                "classical": "⚠️ ",
                "n/a": "·",
                "unaudited": "❓",
            }.get(posture, "❓")
            L.append(
                f"  {mark} {svc.get('service', '?'):<22} [{posture}] "
                f"{svc.get('stack', '')}"
            )
        ssm = st.get("summary", {})
        if ssm:
            L.append(
                f"  → {ssm.get('total', 0)} services · "
                f"{ssm.get('classical', 0)} classical · "
                f"{ssm.get('symmetric', 0)} symmetric · "
                f"{ssm.get('hybrid-pq', 0)} hybrid-pq · "
                f"{ssm.get('n/a', 0)} n/a · "
                f"{ssm.get('unaudited', 0)} unaudited"
            )
    L.append("")

    # --- Trend ---
    L.append("── TREND (from pqc-progression.json) ──")
    if not d.get("trend"):
        L.append("  (no ledger snapshots yet — run 'sksecurity pqc-snapshot')")
    else:
        for t in d["trend"]:
            counts = t.get("status_counts", {})
            cstr = " ".join(f"{k}={v}" for k, v in sorted(counts.items()))
            line = f"  {t.get('date', '?')}  {t.get('label', '')}"
            if cstr:
                line += f"  [{cstr}]"
            L.append(line)
            gbk = t.get("group_breakdown")
            if gbk and gbk.get("total"):
                L.append(
                    f"           group-key: {gbk['hybrid']}/{gbk['total']} hybrid"
                )
    L.append("")
    L.append(
        "Honest claim (ecosystem): confidentiality (KEM/at-rest) is hybrid "
        "X25519+ML-KEM-768 (FIPS 203) where migrated/negotiated; signatures + "
        "identity remain CLASSICAL (Phase 2). Many stack services are "
        "classical-TLS / symmetric / n/a — reported honestly, unknowns flagged "
        "'unaudited'. NOT quantum-resistant end-to-end; no global claim."
    )
    return "\n".join(L)
