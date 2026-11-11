"""fs sweep tests on a synthetic tree. Fake credentials are built by string
concatenation so a gitleaks scan of this file stays clean."""

import os
import subprocess

import pytest

from sksecurity.sweeps import fs

FAKE_TOKEN = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
FAKE_PW = "Zx9" + "Qw7" + "Lm4" + "Rt2"


@pytest.fixture(autouse=True)
def _no_gitleaks(monkeypatch):
    monkeypatch.setenv("SKSECURITY_GITLEAKS", "/nonexistent/gitleaks")
    monkeypatch.setenv("PATH", "/usr/bin:/bin")


def _git(*args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True,
                   env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"})


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "tree"
    repo = root / "repo"
    repo.mkdir(parents=True)
    _git("init", "-q", cwd=repo)
    _git("remote", "add", "origin", "https://u:" + FAKE_TOKEN + "@github.com/x/y.git", cwd=repo)
    (repo / ".env").write_text("WALLET_KEY=" + FAKE_PW + "\n")
    (repo / "README.md").write_text("hi")
    _git("add", ".env", "README.md", cwd=repo)
    _git("commit", "-qm", "x", cwd=repo)
    sd = root / "systemd" / "user"
    sd.mkdir(parents=True)
    (sd / "fake.service").write_text(
        "[Service]\nEnvironment=\"NVIDIA_API_KEY=" + FAKE_PW + "\" LANG=C\n"
        "Environment=SOME_TOKEN=%t\n")
    sess = root / "sessions"
    sess.mkdir()
    (sess / "a.jsonl").write_text(
        '{"t":"psql postgresql://app:' + FAKE_PW + '@localhost:5432/db"}\n'
        '{"t":"postgresql://app:password@localhost/db"}\n')
    ex = root / "conf"
    ex.mkdir()
    secret = ex / "prod.env"
    secret.write_text("A=1\n")
    secret.chmod(0o644)
    good = ex / "ok.env"
    good.write_text("A=1\n")
    good.chmod(0o600)
    return root


def _by_class(findings):
    out = {}
    for f in findings:
        out.setdefault(f.klass, []).append(f)
    return out


def test_all_native_rules(tree):
    fs_findings = fs.run(root=str(tree))
    c = _by_class(fs_findings)
    assert c["secret.git-remote-credential"][0].severity == "critical"
    assert c["secret.git-remote-credential"][0].kedb == "ke-leak-github-pat-dvre"
    assert c["secret.systemd-env"][0].location.endswith("fake.service:2")
    assert len(c["secret.systemd-env"]) == 1
    assert [f.location.endswith(".env") for f in c["secret.tracked-env"]] == [True]
    assert len(c["secret.dsn-in-transcript"]) == 1
    perms = {os.path.basename(f.location) for f in c["perm.secret-file"]}
    assert "prod.env" in perms and "ok.env" not in perms
    assert c["tool.missing"][0].severity == "low"


def test_no_value_anywhere(tree):
    blob = repr([f.to_dict() for f in fs.run(root=str(tree))])
    assert FAKE_TOKEN not in blob and FAKE_PW not in blob


def test_report_only_leaves_tree_untouched(tree):
    def snap():
        return sorted((str(p), p.stat().st_mode, p.stat().st_mtime_ns)
                      for p in tree.rglob("*") if ".git/" not in str(p))
    before = snap()
    fs.run(root=str(tree))
    assert snap() == before


def test_fingerprints_stable(tree):
    a = {f.fingerprint for f in fs.run(root=str(tree))}
    b = {f.fingerprint for f in fs.run(root=str(tree))}
    assert a == b


def test_perm_dir_writable(tmp_path):
    d = tmp_path / "t" / "d"
    d.mkdir(parents=True)
    f = d / "api.token"
    f.write_text("x")
    f.chmod(0o600)
    d.chmod(0o777)
    c = _by_class(fs.run(root=str(tmp_path / "t")))
    assert "perm.secret-dir" in c and "perm.secret-file" not in c


def test_exclude_and_allow_config(tree, tmp_path):
    yaml = pytest.importorskip("yaml")
    cfg = tmp_path / "c.yaml"
    cfg.write_text(yaml.safe_dump({"exclude": [str(tree / "sessions") + "/*"],
                                   "allow": [str(tree / "conf") + "/*"]}))
    c = _by_class(fs.run(root=str(tree), config=str(cfg)))
    assert "secret.dsn-in-transcript" not in c
    assert "prod.env" not in {os.path.basename(f.location) for f in c.get("perm.secret-file", [])}


def test_time_budget(tree):
    c = _by_class(fs.run(root=str(tree), time_budget="0.000001"))
    assert "sweep.truncated" in c


def test_gitleaks_stub_parsed_and_value_dropped(tree, tmp_path, monkeypatch):
    stub = tmp_path / "gl"
    stub.write_text(
        "#!/bin/sh\nwhile [ $# -gt 0 ]; do [ \"$1\" = --report-path ] && P=$2; shift; done\n"
        "printf '[{\"RuleID\":\"private-key\",\"File\":\"%s/x.pem\",\"StartLine\":3,"
        "\"Secret\":\"REDACTED\",\"Match\":\"REDACTED\"}]' \"" + str(tree) + "\" > \"$P\"\n")
    stub.chmod(0o755)
    monkeypatch.setenv("SKSECURITY_GITLEAKS", str(stub))
    c = _by_class(fs.run(root=str(tree)))
    g = c["secret.gitleaks"][0]
    assert g.severity == "critical" and g.rule == "private-key"
    assert "tool.missing" not in c
    assert "Secret" not in g.details and "Match" not in g.details
