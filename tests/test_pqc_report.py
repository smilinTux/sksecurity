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


# ---------------------------------------------------------------------------
# PQC Q2 — per-group surface reflects REALITY (hybrid vs classical)
# ---------------------------------------------------------------------------


class _FakeGroup:
    """Duck-typed stand-in for skchat.group.GroupChat (no skchat dep needed)."""

    def __init__(self, suite: str, epoch: int = 0):
        self.id = "abcd1234-0000-0000-0000-000000000000"
        self.kem_suite = suite
        self.epoch = epoch

    @property
    def is_hybrid(self) -> bool:
        return self.kem_suite == "x25519-mlkem768"


def test_group_surface_hybrid_reports_hybrid_pq():
    from sksecurity.pqc_report import build_report, group_surface_for

    g = _FakeGroup("x25519-mlkem768", epoch=2)
    rpt = build_report(surfaces=[group_surface_for(g)])
    s = rpt["surfaces"][0]
    assert s["surface"] == "group-key"
    assert s["active_suite"] == "x25519-mlkem768"
    assert s["status"] == "hybrid-pq"
    assert s["quantum_resistant"] is True
    assert "FIPS 203" in s["fips_refs"]


def test_group_surface_classical_still_classical():
    from sksecurity.pqc_report import build_report, group_surface_for

    g = _FakeGroup("rsa-pgp-wrap-v1")
    rpt = build_report(surfaces=[group_surface_for(g)])
    s = rpt["surfaces"][0]
    assert s["status"] == "classical"
    assert s["quantum_resistant"] is False


def test_default_report_unchanged_still_all_classical_q0_baseline():
    """The DEFAULT report must stay honest (group-key classical) — groups are
    per-group/opt-in until they migrate."""
    from sksecurity.pqc_report import build_report

    rpt = build_report()
    gk = next(s for s in rpt["surfaces"] if s["surface"] == "group-key")
    assert gk["active_suite"] == "rsa-pgp-wrap-v1"
    assert gk["status"] == "classical"


# ---------------------------------------------------------------------------
# PQC Q4 — per-store at-rest surface reflects REALITY (hybrid vs symmetric)
# ---------------------------------------------------------------------------


class _FakeStore:
    """Duck-typed stand-in for skchat.encrypted_store.EncryptedChatHistory."""

    def __init__(self, wrap_suite: str | None):
        self._wrap_suite = wrap_suite

    def crypto_self_report(self) -> dict:
        is_hybrid = self._wrap_suite == "x25519-mlkem768"
        return {
            "surface": "at-rest",
            "wrap_suite": self._wrap_suite or "unwrapped",
            "quantum_resistant": is_hybrid,
        }


def test_atrest_surface_hybrid_reports_hybrid_pq():
    from sksecurity.pqc_report import atrest_surface_for, build_report

    store = _FakeStore("x25519-mlkem768")
    rpt = build_report(surfaces=[atrest_surface_for(store)])
    s = rpt["surfaces"][0]
    assert s["surface"] == "at-rest"
    assert s["active_suite"] == "x25519-mlkem768"
    assert s["status"] == "hybrid-pq"
    assert s["quantum_resistant"] is True
    assert "FIPS 203" in s["fips_refs"]
    assert "fingerprint" in s["note"].lower()  # documents the fixed bug


def test_atrest_surface_unmigrated_still_symmetric():
    from sksecurity.pqc_report import atrest_surface_for, build_report

    store = _FakeStore(None)
    rpt = build_report(surfaces=[atrest_surface_for(store)])
    s = rpt["surfaces"][0]
    assert s["active_suite"] == "aes256-gcm-v1"
    assert s["status"] == "symmetric"
    assert s["quantum_resistant"] is True  # symmetric is quantum-acceptable


def test_default_report_atrest_still_symmetric_baseline():
    """The DEFAULT report keeps at-rest as the symmetric baseline (Q4 is opt-in)."""
    from sksecurity.pqc_report import build_report

    rpt = build_report()
    ar = next(s for s in rpt["surfaces"] if s["surface"] == "at-rest")
    assert ar["active_suite"] == "aes256-gcm-v1"
    assert ar["status"] == "symmetric"
