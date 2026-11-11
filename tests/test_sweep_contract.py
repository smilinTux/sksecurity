import pytest
from click.testing import CliRunner

from sksecurity.cli import cli
from sksecurity.findings import Finding, make_fingerprint, value_digest
from sksecurity.report import report


def test_fingerprint_stable_and_value_free():
    d = value_digest("hunter2hunter2")
    assert "hunter2" not in d
    assert make_fingerprint("fs", "x", "/a", d) == make_fingerprint("fs", "x", "/a", d)


def test_bad_severity_rejected():
    with pytest.raises(ValueError):
        Finding("fs", "x", "urgent", "/a", "s", "fp")


def test_report_stub_summary():
    f = Finding("fs", "x", "high", "/a", "s", "fp")
    out = report([f], sweep="fs")
    assert out["total"] == 1 and out["by_severity"] == {"high": 1} and out["dry_run"]


def test_unknown_sweep_errors():
    r = CliRunner().invoke(cli, ["sweep", "nope"])
    assert r.exit_code != 0
