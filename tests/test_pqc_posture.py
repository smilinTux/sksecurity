"""PQC POSTURE / coverage self-report — the honest 6-surface table.

The posture report answers a single question per security surface: is the
hybrid-PQ protection the **default** (``hybrid-pq``), merely **available /
opt-in / negotiated** (``gated``), or **absent** (``classical``)? It is grounded
in the REAL wire-tags shipping in the ecosystem (``pqdr1`` DM-ratchet capability,
``kem_suite`` / ``x25519-mlkem768`` group KEM, ``aqid:`` + ``pqroute1`` metadata,
``sig_suite`` signatures, ``wrap_suite`` at-rest, and the classical transport
channel) — never an out-of-band assumption.

Honesty discipline (sk-standards CRYPTOGRAPHY_STANDARD / CRYPTO_AGILITY_STANDARD):
never "quantum-proof" / "quantum-safe" / "unbreakable" / unconditional "end-to-end
post-quantum"; a hybrid leg is secure iff EITHER X25519 or ML-KEM-768 holds; cite
FIPS 203 (ML-KEM) / FIPS 204 (ML-DSA).
"""

from __future__ import annotations

import pytest

from sksecurity.pqc_posture import (
    POSTURE_CLASSICAL,
    POSTURE_GATED,
    POSTURE_HYBRID,
    SURFACE_ORDER,
    build_posture,
    classify_posture,
    format_posture,
)

_FORBIDDEN = (
    "quantum-proof",
    "quantum proof",
    "quantum-safe",
    "quantum safe",
    "unbreakable",
    "unconditional",
    "end-to-end quantum",
    "end-to-end post-quantum",
)


# --- the 3-way classifier (the net-new logic) ------------------------------

def test_classify_default_hybrid_is_hybrid_pq():
    assert classify_posture(default_is_hybrid=True, hybrid_available=True) == POSTURE_HYBRID


def test_classify_available_but_not_default_is_gated():
    assert classify_posture(default_is_hybrid=False, hybrid_available=True) == POSTURE_GATED


def test_classify_no_pq_path_is_classical():
    assert classify_posture(default_is_hybrid=False, hybrid_available=False) == POSTURE_CLASSICAL


def test_three_postures_are_distinct():
    assert len({POSTURE_HYBRID, POSTURE_GATED, POSTURE_CLASSICAL}) == 3


# --- coverage: all six canonical surfaces, in order ------------------------

def test_surface_order_is_the_six_canonical_surfaces():
    assert SURFACE_ORDER == [
        "dm-ratchet",
        "group",
        "metadata",
        "identity-sig",
        "at-rest",
        "transport",
    ]


def test_static_posture_reports_all_six_surfaces_in_order():
    rpt = build_posture(live=False)
    got = [s["surface"] for s in rpt["surfaces"]]
    assert got == SURFACE_ORDER


def test_every_surface_carries_a_real_wire_tag():
    rpt = build_posture(live=False)
    tags = {s["surface"]: s["wire_tag"] for s in rpt["surfaces"]}
    assert tags["dm-ratchet"] == "pqdr1"
    assert tags["group"] == "kem_suite"
    assert tags["identity-sig"] == "sig_suite"
    assert tags["at-rest"] == "wrap_suite"
    # metadata is addressed by aqid: + sealed by pqroute1 — both must appear.
    assert "aqid" in tags["metadata"] and "pqroute1" in tags["metadata"]
    # transport channel is the classical underlay (WireGuard/TLS X25519).
    assert tags["transport"]


def test_every_surface_names_its_hybrid_suite_grounded_in_x25519_mlkem768():
    rpt = build_posture(live=False)
    for s in rpt["surfaces"]:
        # Each surface either has a real hybrid suite or is honestly classical.
        if s["posture"] in (POSTURE_HYBRID, POSTURE_GATED):
            assert s["hybrid_suite"], s["surface"]


# --- honest postures shipping today ----------------------------------------

def test_static_postures_match_reality():
    rpt = build_posture(live=False)
    posture = {s["surface"]: s["posture"] for s in rpt["surfaces"]}
    # Nothing is UNCONDITIONALLY hybrid by default yet → everything PQ is gated;
    # the transport channel has no PQ path at all → classical.
    assert posture["dm-ratchet"] == POSTURE_GATED
    assert posture["group"] == POSTURE_GATED
    assert posture["metadata"] == POSTURE_GATED
    assert posture["identity-sig"] == POSTURE_GATED
    assert posture["at-rest"] == POSTURE_GATED
    assert posture["transport"] == POSTURE_CLASSICAL


def test_hybrid_or_gated_surfaces_cite_fips():
    rpt = build_posture(live=False)
    for s in rpt["surfaces"]:
        if s["posture"] in (POSTURE_HYBRID, POSTURE_GATED):
            refs = " ".join(s["fips_refs"])
            assert "FIPS 203" in refs or "FIPS 204" in refs, s["surface"]


def test_summary_counts_match_surfaces():
    rpt = build_posture(live=False)
    sm = rpt["summary"]
    assert sm["total"] == len(SURFACE_ORDER)
    assert sm["hybrid_pq"] + sm["gated"] + sm["classical"] == sm["total"]
    assert sm["gated"] == 5
    assert sm["classical"] == 1
    assert sm["hybrid_pq"] == 0


# --- the honest table -------------------------------------------------------

def test_format_posture_is_a_table_with_all_surfaces():
    out = format_posture(build_posture(live=False))
    for surface in SURFACE_ORDER:
        assert surface in out
    # the three posture words show up in the rendered table
    assert POSTURE_GATED in out
    assert POSTURE_CLASSICAL in out


def test_no_forbidden_overclaim_anywhere_static():
    rpt = build_posture(live=False)
    blob = (format_posture(rpt) + " " + rpt["honest_claim"]).lower()
    for s in rpt["surfaces"]:
        blob += " " + s["note"].lower()
    for bad in _FORBIDDEN:
        assert bad not in blob, bad


def test_honest_claim_is_present_and_non_overclaiming():
    rpt = build_posture(live=False)
    claim = rpt["honest_claim"].lower()
    assert claim
    # must name the hybrid construction honestly + the FIPS anchor
    assert "x25519" in claim and "ml-kem-768" in claim
    assert "fips 203" in claim
    # must NOT assert global / end-to-end PQ
    assert "end-to-end" not in claim or "not" in claim


# --- live mode is additive + can only UP-rate from real evidence -----------

def test_live_mode_returns_all_six_surfaces_too():
    rpt = build_posture(live=True)
    assert [s["surface"] for s in rpt["surfaces"]] == SURFACE_ORDER


def test_live_mode_never_overclaims_transport_as_hybrid():
    # The transport channel has no PQ leg; live evidence must never flip it.
    rpt = build_posture(live=True)
    transport = next(s for s in rpt["surfaces"] if s["surface"] == "transport")
    assert transport["posture"] == POSTURE_CLASSICAL


def test_no_forbidden_overclaim_anywhere_live():
    rpt = build_posture(live=True)
    blob = (format_posture(rpt) + " " + rpt["honest_claim"]).lower()
    for s in rpt["surfaces"]:
        blob += " " + s["note"].lower()
    for bad in _FORBIDDEN:
        assert bad not in blob, bad
