import json
import subprocess

import pytest

from sksecurity.sweeps import deps, get

CANNED = {
    "dependencies": [
        {"name": "aiohttp", "version": "3.13.3", "vulns": [
            {"id": "PYSEC-1", "fix_versions": ["3.14.1", "3.15.0"],
             "aliases": ["CVE-2026-1", "GHSA-aaaa"], "description": "long text"}]},
        {"name": "oldlib", "version": "1.0", "vulns": [
            {"id": "GHSA-nofix", "fix_versions": [], "aliases": []}]},
        {"name": "clean", "version": "2.0", "vulns": []},
        {"name": "capauth", "skip_reason": "Dependency not found on PyPI: capauth (0.3.dev8)"},
    ],
    "fixes": [],
}


class Proc:
    def __init__(self, out="", err="", rc=0):
        self.stdout, self.stderr, self.returncode = out, err, rc


@pytest.fixture
def env(tmp_path, monkeypatch):
    venv = tmp_path / "venv"
    (venv / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
    monkeypatch.setattr(deps, "find_tool", lambda: "/bin/pip-audit")
    monkeypatch.setattr(deps, "load_config", lambda: {})
    monkeypatch.setattr(deps, "CACHE_PATH", str(tmp_path / "osv.json"))
    return venv


def _patch_run(monkeypatch, fn):
    monkeypatch.setattr(deps.subprocess, "run", fn)


def test_registered():
    assert get("deps") is deps.run


def test_findings_osv_down_falls_back(env, monkeypatch):
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return Proc(json.dumps(CANNED), rc=1)  # pip-audit exits 1 when vulns found

    def boom(_id):
        raise OSError("unreachable")

    _patch_run(monkeypatch, fake_run)
    monkeypatch.setattr(deps, "_osv_fetch", boom)
    fs = deps.run(venv=str(env))
    assert "--path" in calls[0] and "--format" in calls[0]
    assert {f.location: f.severity for f in fs} == {
        "%s: aiohttp==3.13.3" % env: "high", "%s: oldlib==1.0" % env: "medium"}
    a = next(f for f in fs if "aiohttp" in f.location)
    assert a.klass == "dep.vuln"
    assert "PYSEC-1" in a.summary and "CVE-2026-1" in a.summary and "GHSA-aaaa" in a.summary
    assert a.remediation == "upgrade to 3.14.1, 3.15.0"
    assert next(f for f in fs if "oldlib" in f.location).remediation == "no fix released"
    assert not any("capauth" in f.location for f in fs)  # editable skipped cleanly
    assert deps.LAST_STATS["packages_checked"] == 3 and deps.LAST_STATS["packages_skipped"] == 1


def test_osv_failure_stops_further_lookups(env, monkeypatch):
    _patch_run(monkeypatch, lambda cmd, **kw: Proc(json.dumps(CANNED)))
    n = []

    def boom(_id):
        n.append(_id)
        raise OSError("down")

    monkeypatch.setattr(deps, "_osv_fetch", boom)
    deps.run(venv=str(env))
    assert len(n) == 1


def test_critical_from_osv_and_cache(env, monkeypatch, tmp_path):
    _patch_run(monkeypatch, lambda cmd, **kw: Proc(json.dumps(CANNED)))
    monkeypatch.setattr(deps, "_osv_fetch", lambda i: 9.8 if i == "GHSA-aaaa" else None)
    fs = deps.run(venv=str(env))
    assert next(f for f in fs if "aiohttp" in f.location).severity == "critical"
    assert json.loads((tmp_path / "osv.json").read_text())["GHSA-aaaa"]["score"] == 9.8
    # second run served from cache, no network
    monkeypatch.setattr(deps, "_osv_fetch", lambda i: (_ for _ in ()).throw(AssertionError("net")))
    fs2 = deps.run(venv=str(env))
    assert next(f for f in fs2 if "aiohttp" in f.location).severity == "critical"


def test_fingerprint_ignores_version(env, monkeypatch):
    monkeypatch.setattr(deps, "_osv_fetch", lambda i: None)
    _patch_run(monkeypatch, lambda cmd, **kw: Proc(json.dumps(CANNED)))
    a = deps.run(venv=str(env))
    bumped = json.loads(json.dumps(CANNED))
    bumped["dependencies"][0]["version"] = "3.13.4"
    _patch_run(monkeypatch, lambda cmd, **kw: Proc(json.dumps(bumped)))
    b = deps.run(venv=str(env))
    fa = {f.details["package"]: f.fingerprint for f in a}
    fb = {f.details["package"]: f.fingerprint for f in b}
    assert fa["aiohttp"] == fb["aiohttp"]
    assert a[0].details["version"] != b[0].details["version"]


def test_tool_missing(monkeypatch):
    monkeypatch.setattr(deps, "find_tool", lambda: None)
    fs = deps.run()
    assert len(fs) == 1 and fs[0].klass == "tool.missing" and fs[0].severity == "low"


def test_env_failure_is_one_low_finding_and_continues(tmp_path, monkeypatch):
    for n in ("a", "b"):
        (tmp_path / n / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
    monkeypatch.setattr(deps, "find_tool", lambda: "/bin/pip-audit")
    monkeypatch.setattr(deps, "load_config", lambda: {"venvs": [str(tmp_path / "a"), str(tmp_path / "b")]})
    monkeypatch.setattr(deps, "CACHE_PATH", str(tmp_path / "osv.json"))
    monkeypatch.setattr(deps, "_osv_fetch", lambda i: None)

    def fake_run(cmd, **kw):
        if str(tmp_path / "a") in " ".join(cmd):
            raise subprocess.TimeoutExpired(cmd, 1)
        return Proc(json.dumps(CANNED))

    _patch_run(monkeypatch, fake_run)
    fs = deps.run(requirements="/nonexistent")
    errs = [f for f in fs if f.klass == "tool.error"]
    assert len(errs) == 1 and errs[0].severity == "low" and str(tmp_path / "a") in errs[0].location
    assert any(f.klass == "dep.vuln" for f in fs)


def test_garbage_output_is_tool_error(env, monkeypatch):
    _patch_run(monkeypatch, lambda cmd, **kw: Proc("not json", "boom", 2))
    fs = deps.run(venv=str(env))
    assert [f.klass for f in fs] == ["tool.error"]


def test_discovery_excludes_pip_audit(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    for n in ("pip-audit", "skops"):
        (tmp_path / ".venvs" / n).mkdir(parents=True)
    got = deps.discover_envs([], [])
    assert [p.rsplit("/", 1)[-1] for p in got] == ["skops"]


def test_requirements_only_pinned(tmp_path):
    ok, bad = tmp_path / "requirements.txt", tmp_path / "requirements-dev.txt"
    ok.write_text("# c\nrequests==2.0\nclick==8.1 ; python_version>'3'\n")
    bad.write_text("requests>=2\n")
    assert deps._pinned_only(str(ok)) and not deps._pinned_only(str(bad))


def test_requirements_uses_no_deps(tmp_path, monkeypatch):
    r = tmp_path / "requirements.txt"
    r.write_text("aiohttp==3.13.3\n")
    monkeypatch.setattr(deps, "find_tool", lambda: "/bin/pip-audit")
    monkeypatch.setattr(deps, "load_config", lambda: {})
    monkeypatch.setattr(deps, "CACHE_PATH", str(tmp_path / "osv.json"))
    monkeypatch.setattr(deps, "_osv_fetch", lambda i: None)
    seen = []
    _patch_run(monkeypatch, lambda cmd, **kw: seen.append(cmd) or Proc(json.dumps(CANNED)))
    deps.run(requirements=str(r))
    assert "--no-deps" in seen[0] and "--disable-pip" in seen[0] and "-r" in seen[0]


def test_cvss3_score():
    assert deps._cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert deps._cvss3_score("garbage") is None
