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
    assert perms == {"conf", "repo"}  # one finding per directory; ok.env (0600) not counted
    conf = next(f for f in c["perm.secret-file"] if f.location.endswith("conf"))
    assert conf.details["files"] == ["prod.env"] and conf.details["count"] == 1
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
    sd = d / "secrets"
    sd.mkdir()
    f = sd / "api.key"
    f.write_text("x")
    f.chmod(0o600)
    sd.chmod(0o777)
    c = _by_class(fs.run(root=str(tmp_path / "t")))
    assert "perm.secret-dir" in c and "perm.secret-file" not in c


def test_exclude_and_allow_config(tree, tmp_path):
    yaml = pytest.importorskip("yaml")
    cfg = tmp_path / "c.yaml"
    cfg.write_text(yaml.safe_dump({"exclude": [str(tree / "sessions") + "/*"],
                                   "allow": [str(tree / "conf") + "/*"]}))
    c = _by_class(fs.run(root=str(tree), config=str(cfg)))
    assert "secret.dsn-in-transcript" not in c
    assert not any(f.location.endswith("conf") for f in c.get("perm.secret-file", []))


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


# ------------------------------------------------------- noise control ------

STUB = '''#!{py}
import json, os, sys
a = sys.argv
target = a[a.index("dir") + 1]
rp = a[a.index("--report-path") + 1]
with open(os.environ["STUB_LOG"], "a") as fh:
    fh.write(target + "\\n")
recs = json.load(open(os.environ["STUB_RECORDS"]))
json.dump([r for r in recs if r["File"].startswith(target + "/")], open(rp, "w"))
'''


@pytest.fixture
def stub(tmp_path, monkeypatch):
    import sys
    path = tmp_path / "glstub"
    path.write_text(STUB.format(py=sys.executable))
    path.chmod(0o755)
    log = tmp_path / "stub.log"
    recs = tmp_path / "recs.json"
    monkeypatch.setenv("SKSECURITY_GITLEAKS", str(path))
    monkeypatch.setenv("STUB_LOG", str(log))
    monkeypatch.setenv("STUB_RECORDS", str(recs))

    def setup(records):
        import json
        recs.write_text(json.dumps(records))
        log.write_text("")
        return log
    return setup


def _rec(path, rule="generic-api-key", line=1, c0=1, c1=40):
    return {"RuleID": rule, "File": str(path), "StartLine": line, "EndLine": line,
            "StartColumn": c0, "EndColumn": c1, "Secret": "REDACTED", "Match": "REDACTED"}


def test_same_value_in_many_files_is_one_finding(tmp_path, stub):
    root = tmp_path / "r"
    line = "api_key = '" + FAKE_PW + "xx'\n"
    paths = []
    for n in ("a", "b", "c"):
        (root / n).mkdir(parents=True)
        p = root / n / "conf.yaml"
        p.write_text(line)
        paths.append(p)
    other = root / "a" / "other.yaml"
    other.write_text("api_key = '" + FAKE_PW + "yy'\n")
    stub([_rec(p, c1=len(line)) for p in paths] + [_rec(other, c1=len(line))])
    fs_findings = [f for f in fs.run(root=str(root), gitleaks_split="off")
                   if f.klass == "secret.gitleaks"]
    assert len(fs_findings) == 2  # two distinct values, not four hits
    big = max(fs_findings, key=lambda f: f.details["location_count"])
    assert big.details["location_count"] == 3 and len(big.details["locations"]) == 3
    assert FAKE_PW not in repr([f.to_dict() for f in fs_findings])
    again = [f for f in fs.run(root=str(root), gitleaks_split="off") if f.klass == "secret.gitleaks"]
    assert {f.fingerprint for f in again} == {f.fingerprint for f in fs_findings}


def test_generic_rules_medium_in_transcripts_high_elsewhere(tmp_path, stub):
    root = tmp_path / "r"
    (root / "sessions").mkdir(parents=True)
    (root / "conf").mkdir()
    t = root / "sessions" / "x.jsonl"
    c = root / "conf" / "app.yaml"
    t.write_text("k = " + FAKE_PW + "aa\n")
    c.write_text("k = " + FAKE_PW + "bb\n")
    stub([_rec(t), _rec(c), _rec(c, rule="github-pat", line=1)])
    got = {(os.path.basename(f.location.split(":")[0]), f.rule): f.severity
           for f in fs.run(root=str(root), gitleaks_split="off") if f.klass == "secret.gitleaks"}
    assert got[("x.jsonl", "generic-api-key")] == "medium"
    assert got[("app.yaml", "generic-api-key")] == "high"
    assert got[("app.yaml", "github-pat")] == "critical"


def test_dsn_same_password_across_transcripts_is_one_finding(tmp_path):
    root = tmp_path / "r"
    (root / "sessions").mkdir(parents=True)
    for n in ("a", "b", "c"):
        (root / "sessions" / f"{n}.jsonl").write_text(
            '{"t":"psql postgresql://app:' + FAKE_PW + '@localhost/db"}\n')
    (root / "sessions" / "d.jsonl").write_text(
        '{"t":"psql postgresql://app:' + FAKE_PW + 'ZZ@localhost/db"}\n')
    dsn = [f for f in fs.run(root=str(root)) if f.klass == "secret.dsn-in-transcript"]
    assert len(dsn) == 2
    assert max(f.details["location_count"] for f in dsn) == 3


def test_big_roots_split_into_units_with_own_budget(tmp_path, stub):
    root = tmp_path / "r"
    for n in ("a", "b"):
        (root / n).mkdir(parents=True)
        (root / n / "f.txt").write_text("x")
    (root / "top.txt").write_text("x")
    log = stub([])
    fs.run(root=str(root))
    targets = sorted(log.read_text().split())
    assert targets == sorted([str(root), str(root / "a"), str(root / "b")])


def test_duplicate_worktrees_skipped_for_gitleaks(tmp_path, stub):
    main = tmp_path / "clawd" / "repo"
    main.mkdir(parents=True)
    _git("init", "-q", cwd=main)
    (main / "README.md").write_text("hi")
    _git("add", "README.md", cwd=main)
    _git("commit", "-qm", "x", cwd=main)
    wts = tmp_path / "wts"
    wts.mkdir()
    _git("worktree", "add", "-q", "-b", "feat", str(wts / "repo.feat"), cwd=main)
    # a worktree whose main checkout is NOT under a scanned root is still scanned
    lone = tmp_path / "elsewhere" / "lone"
    lone.mkdir(parents=True)
    _git("init", "-q", cwd=lone)
    (lone / "README.md").write_text("hi")
    _git("add", "README.md", cwd=lone)
    _git("commit", "-qm", "x", cwd=lone)
    _git("worktree", "add", "-q", "-b", "feat", str(wts / "lone.feat"), cwd=lone)
    yaml = pytest.importorskip("yaml")
    cfg = tmp_path / "c.yaml"
    cfg.write_text(yaml.safe_dump({"roots": [str(tmp_path / "clawd"), str(wts)]}))
    log = stub([])
    fs.run(config=str(cfg))
    targets = log.read_text().split()
    assert str(wts / "repo.feat") not in targets
    assert str(wts / "lone.feat") in targets
    assert fs.LAST_STATS["duplicate_worktrees_skipped"] == 1
    log2 = stub([])
    fs.run(config=str(cfg), gitleaks_skip_duplicate_worktrees="off")
    assert str(wts / "repo.feat") in log2.read_text().split()


def test_per_root_budget_timeout_is_one_unit_error_and_marks_partial(tmp_path, monkeypatch):
    import sys
    slow = tmp_path / "slow"
    slow.write_text("#!%s\nimport time\ntime.sleep(30)\n" % sys.executable)
    slow.chmod(0o755)
    monkeypatch.setenv("SKSECURITY_GITLEAKS", str(slow))
    root = tmp_path / "r"
    (root / "a").mkdir(parents=True)
    c = _by_class(fs.run(root=str(root), gitleaks_budget="1"))
    assert [f.severity for f in c["tool.error"]] == ["low"]
    assert "sweep.truncated" in c


def test_perm_findings_are_narrow_and_per_directory(tmp_path):
    root = tmp_path / "r"
    (root / "src").mkdir(parents=True)
    for n in ("token_utils.py", "secret_notes.md", "credentials.json", "api.token"):
        (root / "src" / n).write_text("x")  # names alone are not enough
    (root / "envs").mkdir()
    for n in ("a.env", "b.env", "c.env"):
        p = root / "envs" / n
        p.write_text("A=1\n")
        p.chmod(0o644)
    (root / "certs").mkdir()
    k = root / "certs" / "srv.pem"
    k.write_text("x")
    k.chmod(0o644)
    perms = [f for f in fs.run(root=str(root)) if f.klass == "perm.secret-file"]
    assert sorted(os.path.basename(f.location) for f in perms) == ["certs", "envs"]
    envs = next(f for f in perms if f.location.endswith("envs"))
    assert envs.details["count"] == 3 and envs.details["files"] == ["a.env", "b.env", "c.env"]
