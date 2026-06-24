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


# ---------------------------------------------------------------------------
# Confidentiality cut-over — build_live_report honesty (Entry #6).
# ---------------------------------------------------------------------------

from sksecurity.pqc_report import build_live_report  # noqa: E402


def test_live_report_has_group_breakdown_and_does_not_overclaim(monkeypatch):
    """Live report carries a real group_breakdown and never overclaims."""
    rpt = build_live_report()
    assert "group_breakdown" in rpt
    gb = rpt["group_breakdown"]
    assert set(gb) == {"total", "hybrid", "classical"}
    assert gb["hybrid"] + gb["classical"] == gb["total"]
    claim = rpt["honest_claim"].lower()
    assert "quantum-proof" not in claim
    assert "unbreakable" not in claim
    # identity must never be reported quantum-resistant by the cut-over report.
    ident = next(s for s in rpt["surfaces"] if s["surface"] == "identity")
    assert ident["quantum_resistant"] is False


def test_live_report_group_surface_honest_about_mixed_state(monkeypatch):
    """When some groups are classical, the group-key surface stays classical
    with a mixed-state note — never falsely hybrid-pq."""
    import sksecurity.pqc_report as P

    class _G:
        def __init__(self, hybrid):
            self.id = "x" * 8
            self.kem_suite = "x25519-mlkem768" if hybrid else "rsa-pgp-wrap-v1"
            self.epoch = 1 if hybrid else 0
            self.is_hybrid = hybrid

    # 1 hybrid + 1 classical → surface must NOT claim hybrid-pq globally.
    monkeypatch.setattr(P, "_iter_live_groups", lambda: [_G(True), _G(False)])
    monkeypatch.setattr(P, "_live_store_surface", lambda: None)
    rpt = P.build_live_report()
    gk = next(s for s in rpt["surfaces"] if s["surface"] == "group-key")
    assert gk["status"] == "classical"
    assert "1/2" in gk["note"] or "hybrid-pq for 1" in gk["note"]
    assert rpt["group_breakdown"] == {"total": 2, "hybrid": 1, "classical": 0 + 1}


def test_live_report_all_hybrid_groups_report_hybrid(monkeypatch):
    """When EVERY group is hybrid, the surface honestly reads hybrid-pq."""
    import sksecurity.pqc_report as P

    class _G:
        def __init__(self):
            self.id = "y" * 8
            self.kem_suite = "x25519-mlkem768"
            self.epoch = 1
            self.is_hybrid = True

    monkeypatch.setattr(P, "_iter_live_groups", lambda: [_G(), _G()])
    monkeypatch.setattr(P, "_live_store_surface", lambda: None)
    rpt = P.build_live_report()
    gk = next(s for s in rpt["surfaces"] if s["surface"] == "group-key")
    assert gk["status"] == "hybrid-pq"
    assert gk["quantum_resistant"] is True


# ---------------------------------------------------------------------------
# df239fe1 — per-project reports
# ---------------------------------------------------------------------------

from sksecurity.pqc_report import (  # noqa: E402
    build_project_report, known_projects, PROJECT_SURFACES,
)


def test_known_projects_are_the_expected_set():
    assert set(known_projects()) == {"skchat", "skcomms", "capauth", "sksecurity"}


def test_project_report_only_emits_owned_surfaces():
    """capauth owns identity only; skcomms owns envelope-sig (+ payload)."""
    cap = build_project_report("capauth", live=False)
    assert {s["surface"] for s in cap["surfaces"]} == {"identity"}
    assert cap["project"] == "capauth"
    # static (non-live) skcomms = envelope-sig only (payload added only when live)
    comm = build_project_report("skcomms", live=False)
    assert "envelope-sig" in {s["surface"] for s in comm["surfaces"]}


def test_capauth_identity_never_quantum_resistant():
    cap = build_project_report("capauth", live=True)
    ident = next(s for s in cap["surfaces"] if s["surface"] == "identity")
    assert ident["quantum_resistant"] is False
    assert ident["status"] == "classical"


def test_project_report_honest_claim_not_global():
    for proj in known_projects():
        rpt = build_project_report(proj, live=True)
        claim = rpt["honest_claim"].lower()
        for forbidden in ("quantum-proof", "unbreakable", "quantum-safe",
                          "end-to-end quantum"):
            assert forbidden not in claim, (proj, forbidden)


def test_project_report_summary_consistent():
    for proj in known_projects():
        rpt = build_project_report(proj, live=True)
        sm = rpt["summary"]
        assert sm["total_surfaces"] == len(rpt["surfaces"])
        qr = sum(1 for s in rpt["surfaces"] if s["quantum_resistant"])
        assert sm["quantum_resistant"] == qr


def test_unknown_project_raises():
    import pytest
    with pytest.raises(ValueError):
        build_project_report("nope")


# ---------------------------------------------------------------------------
# df239fe1 — JSON ledger + snapshot
# ---------------------------------------------------------------------------

import json as _json  # noqa: E402
from sksecurity.pqc_report import (  # noqa: E402
    append_snapshot, load_ledger, seed_ledger, _snapshot_from_report,
    build_live_report,
)


def test_snapshot_from_report_has_status_counts():
    snap = _snapshot_from_report(build_live_report())
    assert "status_counts" in snap
    assert "summary" in snap
    assert isinstance(snap["surfaces"], list)


def test_append_snapshot_writes_dated_entry(tmp_path, monkeypatch):
    import sksecurity.pqc_report as P
    ledger_path = tmp_path / "pqc-progression.json"
    monkeypatch.setattr(P, "LEDGER_JSON", ledger_path)
    snap = P.append_snapshot(label="unit-test")
    assert ledger_path.exists()
    data = _json.loads(ledger_path.read_text())
    assert data["snapshots"][-1]["label"] == "unit-test"
    assert "date" in snap and "status_counts" in snap


def test_seed_ledger_idempotent(tmp_path, monkeypatch):
    import sksecurity.pqc_report as P
    ledger_path = tmp_path / "pqc-progression.json"
    monkeypatch.setattr(P, "LEDGER_JSON", ledger_path)
    P.seed_ledger()
    n1 = len(_json.loads(ledger_path.read_text())["snapshots"])
    P.seed_ledger()  # idempotent: no duplicate seeds
    n2 = len(_json.loads(ledger_path.read_text())["snapshots"])
    assert n1 == n2 == 6
    # entries 1..6 present
    entries = [s.get("entry") for s in _json.loads(ledger_path.read_text())["snapshots"]]
    assert entries == [1, 2, 3, 4, 5, 6]


# ---------------------------------------------------------------------------
# df239fe1 — SKStacks per-service report
# ---------------------------------------------------------------------------

from sksecurity.pqc_stacks import (  # noqa: E402
    _classify, _parse_services, build_stacks_report, format_stacks_report,
)


def test_parse_services_extracts_names_and_images():
    text = (
        "services:\n"
        "  web:\n"
        "    image: nginx:latest\n"
        "    labels:\n"
        "      traefik.http.routers.x.tls: \"true\"\n"
        "  db:\n"
        "    image: postgres:16-alpine\n"
        "volumes:\n"
        "  data:\n"
    )
    svc = _parse_services(text)
    names = {s["service"] for s in svc}
    assert names == {"web", "db"}
    web = next(s for s in svc if s["service"] == "web")
    assert web["tls"] is True
    db = next(s for s in svc if s["service"] == "db")
    assert "postgres" in db["image"]


def test_classify_unknown_is_unaudited_not_assumed_secure():
    row = _classify({"service": "mystery", "image": "weird/thing:1", "tls": False})
    assert row["posture"] == "unaudited"
    assert row["quantum_resistant"] is False


def test_classify_postgres_is_classical_no_pqc():
    row = _classify({"service": "postgres", "image": "postgres:16-alpine", "tls": False})
    assert row["posture"] == "classical"
    assert row["quantum_resistant"] is False


def test_no_stack_service_is_quantum_resistant():
    """Honesty: no SKStacks service may report quantum-resistant today."""
    try:
        rpt = build_stacks_report()
    except FileNotFoundError:
        import pytest
        pytest.skip("SKStacks descriptors not present in this environment")
    assert rpt["summary"]["hybrid-pq"] == 0
    for s in rpt["services"]:
        assert s["quantum_resistant"] is False
    claim = rpt["honest_claim"].lower()
    assert "none is quantum-resistant" in claim
    assert "quantum-proof" not in claim
    text = format_stacks_report(rpt)
    assert "Per-Service" in text


# ---------------------------------------------------------------------------
# df239fe1 — dashboard
# ---------------------------------------------------------------------------

from sksecurity.pqc_report import build_dashboard, format_dashboard  # noqa: E402


def test_dashboard_assembles_all_sections():
    dash = build_dashboard(live=True, include_stacks=True)
    assert "aggregate" in dash
    assert set(dash["projects"]) == set(known_projects())
    assert "stacks" in dash
    assert "trend" in dash
    text = format_dashboard(dash)
    assert "PQC DASHBOARD" in text
    assert "PER-PROJECT" in text
    assert "PER-SERVICE" in text
    assert "TREND" in text
    # ecosystem honest claim present + not overclaiming
    low = text.lower()
    assert "not quantum-resistant end-to-end" in low
    assert "quantum-proof" not in low


def test_dashboard_handles_missing_stacks_gracefully(monkeypatch):
    import sksecurity.pqc_report as P
    # Force the stacks import to fail → unavailable marker, no fabrication.
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "sksecurity.pqc_stacks" or name.endswith("pqc_stacks"):
            raise ImportError("simulated missing stacks")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    dash = P.build_dashboard(include_stacks=True)
    assert dash["stacks"].get("unavailable") is True
