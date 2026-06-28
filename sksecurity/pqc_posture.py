"""PQC POSTURE / coverage self-report — the honest 6-surface table.

This is the *coverage* view that complements the per-surface detail in
:mod:`sksecurity.pqc_report`. Where ``pqc_report`` answers "which suite is this
specific object using?", the **posture** report answers one blunt question for
each of the six security surfaces of the sovereign-comms ecosystem:

    Is the hybrid-PQ protection the DEFAULT, merely AVAILABLE/opt-in, or ABSENT?

→ a three-way label per surface:

    * ``hybrid-pq`` — hybrid X25519+ML-KEM-768 (FIPS 203) is the *unconditional
      default* for new objects on this surface.
    * ``gated``     — a hybrid path EXISTS and is wired, but it is opt-in /
      capability-negotiated / per-object migration, so it is **not** what you get
      unless both sides advertise it (or a store/group is explicitly migrated).
    * ``classical`` — there is no PQ path on this surface today (Shor-breakable
      asymmetric, or a classical channel underlay).

Everything here is grounded in the REAL wire-tags the ecosystem ships (the
contract in ``sk-standards/CRYPTO_AGILITY_STANDARD.md``), never an out-of-band
assumption:

    | surface       | wire-tag(s)                  | hybrid suite        |
    |---------------|------------------------------|---------------------|
    | dm-ratchet    | ``pqdr1`` (RFC-0001 P1 cap)  | ``x25519-mlkem768`` |
    | group         | ``kem_suite``                | ``x25519-mlkem768`` |
    | metadata      | ``aqid:`` + ``pqroute1``     | ``x25519-mlkem768`` |
    | identity-sig  | ``sig_suite``                | ``mldsa65-ed25519-v2`` |
    | at-rest       | ``wrap_suite``               | ``x25519-mlkem768`` |
    | transport     | channel (WireGuard/TLS X25519) | —                 |

HONESTY DISCIPLINE (sk-standards CRYPTOGRAPHY_STANDARD):
    * never "quantum-proof" / "quantum-safe" / "unbreakable" / unconditional
      "end-to-end post-quantum";
    * a hybrid leg is secure iff EITHER the X25519 leg OR the ML-KEM-768 (FIPS
      203) leg holds — that is the whole claim, no more;
    * AES-256-GCM bulk is Grover-only (quantum-acceptable), NOT quantum-broken;
    * ML-DSA/Ed25519 signatures are future-forgery (not HNDL — not retroactive).

This module is ADDITIVE and read-only: it imports nothing that mutates state and
degrades gracefully (live enrichment is best-effort; absence of skchat/skcomms
falls back to the static honest default).
"""

from __future__ import annotations

from dataclasses import dataclass, field

# --- the three postures -----------------------------------------------------

#: hybrid X25519+ML-KEM-768 is the UNCONDITIONAL default for new objects here.
POSTURE_HYBRID = "hybrid-pq"
#: a hybrid path exists but is opt-in / negotiated / per-object migration.
POSTURE_GATED = "gated"
#: no PQ path on this surface today (classical asymmetric or classical channel).
POSTURE_CLASSICAL = "classical"

#: the six canonical surfaces, in report order.
SURFACE_ORDER = [
    "dm-ratchet",
    "group",
    "metadata",
    "identity-sig",
    "at-rest",
    "transport",
]

#: terms a posture report must NEVER emit (the no-overclaim gate).
FORBIDDEN_TERMS = (
    "quantum-proof",
    "quantum proof",
    "quantum-safe",
    "quantum safe",
    "unbreakable",
    "unconditional",
    "end-to-end quantum",
    "end-to-end post-quantum",
)

_HYBRID_KEM = "x25519-mlkem768"
_HYBRID_SIG = "mldsa65-ed25519-v2"
_FIPS_KEM = ["FIPS 203", "RFC 7748", "RFC 5869"]
_FIPS_SIG = ["FIPS 204", "RFC 8032"]


def classify_posture(default_is_hybrid: bool, hybrid_available: bool) -> str:
    """Map two booleans to the three-way posture label (the core logic).

    Args:
        default_is_hybrid: is hybrid-PQ the UNCONDITIONAL default for new objects
            on this surface (not negotiated, not per-object opt-in)?
        hybrid_available: does a hybrid path exist at all (wired + reachable)?

    Returns:
        ``hybrid-pq`` if hybrid is the default, else ``gated`` if a hybrid path
        merely exists, else ``classical``. Honest by construction: a surface is
        only ``hybrid-pq`` when the default truly is hybrid; "available" never
        rounds up to "default".
    """
    if default_is_hybrid:
        return POSTURE_HYBRID
    if hybrid_available:
        return POSTURE_GATED
    return POSTURE_CLASSICAL


@dataclass
class SurfacePosture:
    """One surface's coverage posture, grounded in its real wire-tag(s)."""

    surface: str
    wire_tag: str
    component: str
    default_suite: str
    hybrid_suite: str
    posture: str
    fips_refs: list[str] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "surface": self.surface,
            "wire_tag": self.wire_tag,
            "component": self.component,
            "default_suite": self.default_suite,
            "hybrid_suite": self.hybrid_suite,
            "posture": self.posture,
            "fips_refs": list(self.fips_refs),
            "note": self.note,
        }


def _static_surfaces() -> list[SurfacePosture]:
    """The honest DEFAULT coverage — what the ecosystem ships independent of any
    one operator's live objects. Every PQ surface is ``gated`` (opt-in /
    negotiated / per-object migration); the transport channel is ``classical``."""
    return [
        SurfacePosture(
            surface="dm-ratchet",
            wire_tag="pqdr1",
            component="skchat (DmRatchet / pq_prekeys.RATCHET_CAP)",
            default_suite="x25519-pgp-wrap-v1",
            hybrid_suite=_HYBRID_KEM,
            posture=classify_posture(default_is_hybrid=False, hybrid_available=True),
            fips_refs=_FIPS_KEM,
            note=(
                "1:1 DM confidentiality. NEGOTIATED: hybrid X25519+ML-KEM-768 "
                "(FIPS 203) engages only when BOTH peers advertise the `pqdr1` "
                "ratchet capability + a hybrid prekey; a peer that omits `pqdr1` "
                "stays on the classical PGP-wrap path (never handed an "
                "undecryptable frame). HNDL-exposed while classical. Secure iff "
                "EITHER the X25519 or the ML-KEM-768 leg holds."
            ),
        ),
        SurfacePosture(
            surface="group",
            wire_tag="kem_suite",
            component="skchat (GroupChat.kem_suite / epoch ratchet)",
            default_suite="rsa-pgp-wrap-v1",
            hybrid_suite=_HYBRID_KEM,
            posture=classify_posture(default_is_hybrid=False, hybrid_available=True),
            fips_refs=_FIPS_KEM,
            note=(
                "Group key distribution. A group whose `kem_suite` is "
                "`x25519-mlkem768` distributes a per-epoch secret hybrid-wrapped "
                "to each member (FS + PCS). NEW groups default hybrid, but "
                "existing groups migrate PER-GROUP via `GroupChat.migrate_to_"
                "hybrid()`; un-migrated groups stay classical (HNDL-exposed). "
                "Run with --live to count the real fleet ratio."
            ),
        ),
        SurfacePosture(
            surface="metadata",
            wire_tag="aqid: + pqroute1",
            component="skcomms (anon_transport / pqroute)",
            default_suite="plaintext-routing",
            hybrid_suite=_HYBRID_KEM,
            posture=classify_posture(default_is_hybrid=False, hybrid_available=True),
            fips_refs=_FIPS_KEM,
            note=(
                "Routing-metadata privacy. `aqid:` gives no-identity, unlinkable "
                "addressing (`aqid-v1`, deniable HMAC-SHA256 auth — authenticity "
                "WITHOUT non-repudiation, no body confidentiality). `pqroute1` "
                "hybrid-seals the inner routing metadata + content with "
                "X25519+ML-KEM-768 (FIPS 203) so a harvest-now-decrypt-later "
                "relay cannot link who-talks-to-whom. Both are OPT-IN routing "
                "layers; the default SignedEnvelope still carries plaintext "
                "to/from routing fields."
            ),
        ),
        SurfacePosture(
            surface="identity-sig",
            wire_tag="sig_suite",
            component="capauth / skcomms (SignedEnvelope.sig_suite)",
            default_suite="ed25519-v1",
            hybrid_suite=_HYBRID_SIG,
            posture=classify_posture(default_is_hybrid=False, hybrid_available=True),
            fips_refs=_FIPS_SIG,
            note=(
                "Identity + per-message/challenge signatures. DEFAULT is "
                "classical Ed25519 (`ed25519-v1`). A hybrid Ed25519+ML-DSA-65 "
                "(FIPS 204) signature is AVAILABLE opt-in via "
                "`HybridEnvelopeSigner` / capauth.pqc_identity (either-leg "
                "verify), using a per-signer ML-DSA key SEPARATE from the PGP "
                "root. The ROOT PGP identity key is NOT migrated (Sequoia, "
                "gated). Signature exposure is future-forgery, NOT retroactive "
                "(not HNDL)."
            ),
        ),
        SurfacePosture(
            surface="at-rest",
            wire_tag="wrap_suite",
            component="skchat/sksecurity (encrypted_store DEK wrap, KMS)",
            default_suite="aes256-gcm-v1",
            hybrid_suite=_HYBRID_KEM,
            posture=classify_posture(default_is_hybrid=False, hybrid_available=True),
            fips_refs=_FIPS_KEM,
            note=(
                "At-rest stores. Bulk AES-256-GCM is symmetric (Grover-only, "
                "~128-bit, quantum-acceptable). The DEK key-WRAP layer can be "
                "sealed with hybrid X25519+ML-KEM-768 (FIPS 203, `wrap_suite="
                "x25519-mlkem768`) so a harvested backup is not retroactively "
                "decryptable — AVAILABLE opt-in PER STORE (migrate via "
                "`EncryptedChatHistory.migrate_store()`). Run with --live to "
                "report this operator's real store."
            ),
        ),
        SurfacePosture(
            surface="transport",
            wire_tag="channel: WireGuard/TLS X25519",
            component="skcomms (federated envelope transport / S2S)",
            default_suite="wireguard-x25519 / tls1.3-x25519",
            hybrid_suite="",
            posture=classify_posture(default_is_hybrid=False, hybrid_available=False),
            fips_refs=[],
            note=(
                "The wire CHANNEL underlay (Tailscale/WireGuard or TLS 1.3) keys "
                "with classical X25519 — NO PQ leg at the channel layer, so the "
                "channel is HNDL-exposed on its own. Post-quantum confidentiality "
                "on this ecosystem comes from the MESSAGE layer (dm-ratchet / "
                "group / pqroute1 / at-rest), which seals payloads independently "
                "of the channel; it is NOT provided by the transport itself. "
                "Reported classical honestly rather than borrowing the message "
                "layer's posture."
            ),
        ),
    ]


def _live_enrich(surfaces: list[SurfacePosture]) -> None:
    """Best-effort: UP-rate group / at-rest from the operator's real objects.

    Reuses :func:`sksecurity.pqc_report.build_live_report` (which reads the
    operator's actual groups + at-rest store) and flips a surface to
    ``hybrid-pq`` ONLY when the live evidence unambiguously says so — never a
    down-rate, never the transport (no PQ leg exists to find). Silent no-op if
    skchat/skcomms are unavailable.
    """
    try:
        from .pqc_report import build_live_report
    except Exception:
        return
    try:
        live = build_live_report()
    except Exception:
        return

    by_name = {s.surface: s for s in surfaces}
    live_by = {s["surface"]: s for s in live.get("surfaces", [])}
    gb = live.get("group_breakdown") or {}

    # group: hybrid-pq only when EVERY existing group is hybrid (matches the
    # honesty rule in build_live_report — mixed state never rounds up).
    grp = by_name.get("group")
    if grp is not None:
        total = gb.get("total", 0)
        hybrid = gb.get("hybrid", 0)
        if total and hybrid == total:
            grp.posture = POSTURE_HYBRID
            grp.default_suite = _HYBRID_KEM
            grp.note = (
                f"LIVE: all {total} group(s) on the hybrid epoch-ratchet "
                "(x25519-mlkem768, FIPS 203). HNDL-resistant fleet-wide. Secure "
                "iff EITHER the X25519 or the ML-KEM-768 leg holds."
            )
        elif total:
            grp.note = (
                f"LIVE: hybrid-pq for {hybrid}/{total} group(s); "
                f"{total - hybrid} still classical (HNDL-exposed). New groups "
                "default hybrid; migrate the rest per-group."
            )

    # at-rest: reflect the operator's live store wrap if migrated.
    ar = by_name.get("at-rest")
    if ar is not None:
        live_ar = live_by.get("at-rest")
        if live_ar is not None and live_ar.get("quantum_resistant"):
            ar.posture = POSTURE_HYBRID
            ar.default_suite = _HYBRID_KEM
            ar.note = (
                "LIVE: this operator's store seals the DEK with hybrid "
                "X25519+ML-KEM-768 (FIPS 203). A harvested backup is not "
                "retroactively decryptable. Bulk AES-256-GCM is Grover-only."
            )


def _summary(surfaces: list[SurfacePosture]) -> dict:
    return {
        "total": len(surfaces),
        "hybrid_pq": sum(1 for s in surfaces if s.posture == POSTURE_HYBRID),
        "gated": sum(1 for s in surfaces if s.posture == POSTURE_GATED),
        "classical": sum(1 for s in surfaces if s.posture == POSTURE_CLASSICAL),
    }


def _honest_claim(summary: dict) -> str:
    """The footer claim — states exactly the coverage, never an overclaim."""
    parts = [
        f"PQC coverage posture across {summary['total']} surfaces: "
        f"{summary['hybrid_pq']} hybrid-pq (default), {summary['gated']} gated "
        f"(hybrid available but opt-in / negotiated / per-object), "
        f"{summary['classical']} classical (no PQ path).",
        "Where engaged, the hybrid construction is X25519 + ML-KEM-768 (FIPS "
        "203) for KEMs and Ed25519 + ML-DSA-65 (FIPS 204) for signatures: secure "
        "as long as EITHER leg holds — that is the entire claim.",
        "AES-256-GCM bulk is symmetric (Grover-only, quantum-acceptable). "
        "Signatures are future-forgery exposure, not retroactive (not HNDL).",
        "This is NOT a whole-system post-quantum guarantee: a 'gated' surface "
        "gives classical protection unless both sides negotiate hybrid, and the "
        "transport channel keys classically. Never claim global or cross-surface "
        "post-quantum coverage.",
    ]
    return " ".join(parts)


def build_posture(live: bool = True) -> dict:
    """Build the PQC posture / coverage report (the honest 6-surface table).

    Args:
        live: when True (default), best-effort enrich ``group`` / ``at-rest``
            from the operator's real objects (only ever up-rating to
            ``hybrid-pq`` when the live evidence unambiguously says so). When
            False, report the static honest default coverage. The transport
            surface is never enriched (no PQ leg exists to find).

    Returns:
        dict with ``surfaces`` (ordered per-surface dicts), ``summary`` posture
        counts, and a non-overclaiming ``honest_claim``.
    """
    surfaces = _static_surfaces()
    if live:
        _live_enrich(surfaces)
    summary = _summary(surfaces)
    return {
        "report": "pqc-posture",
        "mode": "live" if live else "static",
        "surfaces": [s.to_dict() for s in surfaces],
        "summary": summary,
        "honest_claim": _honest_claim(summary),
    }


_POSTURE_FLAG = {
    POSTURE_HYBRID: "✅ hybrid-pq",
    POSTURE_GATED: "🟡 gated (opt-in)",
    POSTURE_CLASSICAL: "⚠️  classical",
}


def format_posture(report: dict | None = None) -> str:
    """Render the posture report as an honest, fixed-width coverage table."""
    rpt = report or build_posture()
    lines: list[str] = []
    lines.append("🔐 PQC Posture — coverage self-report (per surface)")
    lines.append("=" * 70)
    lines.append(f"Mode: {rpt['mode']}   (honest claims only — hybrid = either-leg; no overclaims)")
    lines.append("")
    header = f"{'surface':<13} {'posture':<10} {'wire-tag':<26} suite"
    lines.append(header)
    lines.append("-" * 70)
    for s in rpt["surfaces"]:
        suite = s["default_suite"]
        if s["posture"] == POSTURE_GATED and s["hybrid_suite"]:
            suite = f"{s['default_suite']} → {s['hybrid_suite']}"
        elif s["posture"] == POSTURE_HYBRID:
            suite = s["hybrid_suite"] or s["default_suite"]
        lines.append(f"{s['surface']:<13} {s['posture']:<10} {s['wire_tag']:<26} {suite}")
    lines.append("-" * 70)
    lines.append("")
    for s in rpt["surfaces"]:
        flag = _POSTURE_FLAG.get(s["posture"], s["posture"])
        lines.append(f"• {s['surface']:<13} [{s['posture']}] {flag}")
        lines.append(f"    component : {s['component']}")
        lines.append(f"    wire-tag  : {s['wire_tag']}")
        if s["fips_refs"]:
            lines.append(f"    refs      : {', '.join(s['fips_refs'])}")
        lines.append(f"    note      : {s['note']}")
        lines.append("")
    sm = rpt["summary"]
    lines.append(
        f"Summary: {sm['hybrid_pq']} hybrid-pq · {sm['gated']} gated · "
        f"{sm['classical']} classical  (of {sm['total']} surfaces)"
    )
    lines.append("")
    lines.append(f"Honest claim: {rpt['honest_claim']}")
    return "\n".join(lines)
