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

from dataclasses import dataclass, field
from typing import Optional


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
        "Agent/operator PGP signing identity. Shor-breakable; HNDL N/A "
        "(signatures not retroactive). Migrates in Phase 2.",
    ),
    (
        "envelope-sig",
        "skcomms (SignedEnvelope.sig_suite)",
        "ed25519-v1",
        "Per-message detached signature over canonical_bytes. Future-forgery "
        "risk; not HNDL. Migrates in Phase 2.",
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
        "Key-WRAP layer (not the bulk cipher) gets a hybrid KEM in Phase 1 (Q4).",
    ),
]


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
    lines.append("")
    lines.append(f"Honest claim: {rpt['honest_claim']}")
    return "\n".join(lines)
