"""ITIL reporter tests against a tmp ITIL root. skcoord is optional."""


import pytest

pytest.importorskip("skcoord.itil")
from skcoord.itil import ITILManager  # noqa: E402

from sksecurity import integration, report as report_mod  # noqa: E402
from sksecurity.findings import Finding, make_fingerprint  # noqa: E402



def _f(i, sev="high", klass="secret.tracked-env", kedb=None, host="h1"):
    return Finding("fs", klass, sev, f"/x/{i}/.env", f"summary {i}",
                   make_fingerprint("fs", klass, str(i)), rule="r", kedb=kedb,
                   remediation="fix it", host=host)


@pytest.fixture
def itil(tmp_path, monkeypatch):
    home = tmp_path / "itilhome"
    home.mkdir()
    monkeypatch.setenv("SKSECURITY_ITIL_HOME", str(home))
    monkeypatch.setattr("socket.gethostname", lambda: "h1")
    monkeypatch.setattr(ITILManager, "_gtd_emit", lambda *a, **k: None)
    monkeypatch.setattr(ITILManager, "_publish_event", lambda *a, **k: None)
    alerts = []
    monkeypatch.setattr(integration, "alert",
                        lambda event, payload, level="info": alerts.append((event, payload, level)))
    ITILManager(home).ensure_dirs()
    return ITILManager(home), alerts


def test_dry_run_files_nothing(itil):
    mgr, alerts = itil
    out = report_mod.report([_f(1)], "fs", dry_run=True)
    assert out["filed"] == [] and out["dry_run"] and mgr.list_incidents() == [] and alerts == []


def test_per_finding_incident_tags_and_dedup(itil):
    mgr, alerts = itil
    crit = _f(1, "critical", kedb="ke-leak-github-pat-dvre")
    out = report_mod.report([crit, _f(2)], "fs", dry_run=False)
    assert len(out["filed"]) == 2
    incs = {i.id: i for i in mgr.list_incidents()}
    c = next(i for i in incs.values() if f"fp:{crit.fingerprint}" in i.tags)
    assert c.severity.value == "sev2"
    assert {"sksecurity", "sweep:fs", f"class:{crit.klass}",
            "kedb:ke-leak-github-pat-dvre"} <= set(c.tags)
    assert any(i.severity.value == "sev3" for i in incs.values())
    again = report_mod.report([crit, _f(2)], "fs", dry_run=False)
    assert again["filed"] == [] and len(mgr.list_incidents()) == 2
    assert len(alerts) == 2 and alerts[0][2] == "critical" and alerts[0][0] == "sweep_summary"


def test_rollup_one_incident_updated_not_duplicated(itil):
    mgr, _ = itil
    first = report_mod.report([_f(1, "medium"), _f(2, "low")], "fs", dry_run=False)
    assert len(first["filed"]) == 1
    inc = mgr.list_incidents()[0]
    assert inc.severity.value == "sev4" and "2 medium/low findings" in inc.title
    assert inc.title == "sksecurity fs sweep on h1: 2 medium/low findings"
    second = report_mod.report([_f(1, "medium"), _f(2, "low"), _f(3, "medium")], "fs",
                               dry_run=False)
    assert second["filed"] == [] and second["updated"] == [inc.id]
    assert len(mgr.list_incidents()) == 1
    same = report_mod.report([_f(1, "medium"), _f(2, "low"), _f(3, "medium")], "fs",
                             dry_run=False)
    assert same["updated"] == []


def test_cap_spills_into_rollup(itil):
    mgr, _ = itil
    out = report_mod.report([_f(i) for i in range(25)], "fs", dry_run=False)
    incs = mgr.list_incidents()
    per = [i for i in incs if "rollup" not in i.tags]
    roll = [i for i in incs if "rollup" in i.tags]
    assert len(per) == 20 and len(roll) == 1 and out["plan"]["over_cap"] == 5
    assert roll[0].severity.value == "sev3"
    assert "per-run cap" in (roll[0].impact + " ".join(e.get("note", "") for e in roll[0].timeline))


def test_not_seen_event_never_closes(itil):
    mgr, _ = itil
    report_mod.report([_f(1), _f(2)], "fs", dry_run=False)
    out = report_mod.report([_f(1)], "fs", dry_run=False)
    assert len(out["not_seen"]) == 1
    gone = mgr.list_incidents()
    inc = next(i for i in gone if i.id == out["not_seen"][0])
    assert inc.status.value == "detected"
    assert "not seen in sweep at" in inc.timeline[-1]["note"]
    again = report_mod.report([_f(1)], "fs", dry_run=False)
    assert again["not_seen"] == []


def test_partial_run_does_not_claim_not_seen(itil):
    report_mod.report([_f(1)], "fs", dry_run=False)
    trunc = Finding("fs", "sweep.truncated", "low", "time_budget", "s", "fpt")
    out = report_mod.report([trunc], "fs", dry_run=False)
    assert out["not_seen"] == []


def test_other_host_findings_not_marked(itil, monkeypatch):
    mgr, _ = itil
    report_mod.report([_f(1)], "fs", dry_run=False)
    monkeypatch.setattr("socket.gethostname", lambda: "h2")
    out = report_mod.report([], "fs", dry_run=False)
    assert out["not_seen"] == []


def test_no_value_in_incidents(itil):
    mgr, _ = itil
    f = _f(1)
    f.details["digest"] = "abcd1234"
    report_mod.report([f], "fs", dry_run=False)
    blob = repr([i.model_dump() for i in mgr.list_incidents()])
    assert "location=/x/1/.env" in blob and "remediation: fix it" in blob


def test_real_itil_root_untouched(itil):
    from tests.conftest import REAL_HOME
    root = REAL_HOME / ".skcapstone" / "coordination" / "itil" / "incidents"
    before = sorted(p.name for p in root.iterdir()) if root.is_dir() else None
    report_mod.report([_f(1), _f(2, "medium")], "fs", dry_run=False)
    after = sorted(p.name for p in root.iterdir()) if root.is_dir() else None
    assert before == after


def test_without_skcoord_reports_error(monkeypatch):
    monkeypatch.setattr(report_mod, "_manager", lambda: None)
    out = report_mod.report([_f(1)], "fs", dry_run=False)
    assert out["error"] == "itil-unavailable" and out["filed"] == []
