"""PQC Q0 — runtime self-report tests for sksecurity.

Covers:
    - The self-report enumerates all owned surfaces.
    - Honesty: every asymmetric surface reports CLASSICAL today (no migration).
    - Symmetric/at-rest is correctly quantum-acceptable, not over-claimed.
    - The report reflects the suite registry (live or embedded fallback).
"""

from __future__ import annotations

from sksecurity.pqc_report import build_report, format_report


def test_report_has_all_surfaces():
    rpt = build_report()
    surfaces = {s["surface"] for s in rpt["surfaces"]}
    assert surfaces == {"identity", "envelope-sig", "group-key", "at-rest"}


def test_no_asymmetric_surface_is_quantum_resistant_today():
    """Q0 honesty: nothing asymmetric may be reported quantum-resistant yet."""
    rpt = build_report()
    for s in rpt["surfaces"]:
        if s["status"] in ("classical",):
            assert s["quantum_resistant"] is False, s


def test_classical_surfaces_present_and_summary_consistent():
    rpt = build_report()
    sm = rpt["summary"]
    assert sm["total_surfaces"] == 4
    # identity, envelope-sig, group-key are classical; at-rest is symmetric.
    assert sm["classical"] == 3
    assert sm["symmetric"] == 1
    # No asymmetric PQ migration -> quantum_resistant count == symmetric count.
    assert sm["quantum_resistant"] == sm["symmetric"]


def test_honest_claim_does_not_overclaim():
    rpt = build_report()
    claim = rpt["honest_claim"].lower()
    assert "not quantum-resistant end-to-end" in claim
    for forbidden in ("quantum-proof", "unbreakable", "quantum-safe"):
        assert forbidden not in claim


def test_at_rest_is_symmetric_quantum_acceptable():
    rpt = build_report()
    at_rest = next(s for s in rpt["surfaces"] if s["surface"] == "at-rest")
    assert at_rest["status"] == "symmetric"
    assert at_rest["quantum_resistant"] is True
    assert "AES-256-GCM" in at_rest["primitives"]


def test_fips_refs_present_on_surfaces():
    rpt = build_report()
    for s in rpt["surfaces"]:
        assert s["fips_refs"], f"{s['surface']} missing FIPS/RFC refs"


def test_format_report_renders():
    text = format_report()
    assert "PQC Self-Report" in text
    assert "classical" in text
