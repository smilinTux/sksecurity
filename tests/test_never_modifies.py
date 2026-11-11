"""Report-only guarantee: no sweep or screen command moves, deletes, chmods or
edits anything it inspects, by default (Chef, 2026-11-11). HOME is isolated by
tests/conftest.py for every test."""

import hashlib
import os
import stat
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from sksecurity.cli import cli


def _snapshot(root: Path):
    snap = {}
    for p in sorted(root.rglob("*")):
        st = p.lstat()
        digest = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
        snap[str(p.relative_to(root))] = (stat.S_IMODE(st.st_mode), st.st_mtime_ns, digest)
    return snap


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "tree"
    (root / "repo" / ".git").mkdir(parents=True)
    (root / "repo" / ".git" / "config").write_text(
        '[remote "origin"]\n\turl = https://user:' + 'ghp_' + 'A' * 36 + '@github.com/x/y.git\n')
    env = root / "repo" / "app.env"
    env.write_text("API_" + "TOKEN=" + "sk-" + "b" * 40 + "\n")
    os.chmod(env, 0o644)  # deliberately too open: the sweep must report, not fix
    (root / "invoice.pdf.exe").write_bytes(b"MZ\x90\x00not really")
    (root / "notes.txt").write_text("hello\n")
    subprocess.run(["git", "init", "-q", str(root / "repo")], check=False)
    return root


@pytest.mark.parametrize("args", [
    ["sweep", "fs", "--opt", "root={root}"],
    ["sweep", "fs", "--opt", "root={root}", "--format", "json"],
    ["sweep", "mail", "--opt", "dir={root}"],
    ["screen-file", "{root}/invoice.pdf.exe", "{root}/notes.txt"],
    ["guard", "scan", "{root}"],
])
def test_command_leaves_tree_untouched(tree, args, monkeypatch):
    monkeypatch.setenv("SKSECURITY_GITLEAKS", "/nonexistent/gitleaks")  # native rules only, no network
    before = _snapshot(tree)
    result = CliRunner().invoke(cli, [a.format(root=tree) for a in args])
    assert result.exception is None or isinstance(result.exception, SystemExit), result.output
    assert _snapshot(tree) == before


def test_sweep_default_is_dry_run(tree, monkeypatch):
    """Without --report nothing is filed: the reporter is called with dry_run=True."""
    import sksecurity.report as rep
    seen = {}
    real = rep.report
    monkeypatch.setattr(rep, "report", lambda f, sweep, dry_run=True: seen.setdefault("dry", dry_run) or real(f, sweep, dry_run=dry_run))
    CliRunner().invoke(cli, ["sweep", "fs", "--opt", f"root={tree}"])
    assert seen.get("dry") is True


def test_fs_sweep_reports_the_planted_problems(tree, monkeypatch):
    """Not vacuous: the untouched tree really did contain findings."""
    import json
    monkeypatch.setenv("SKSECURITY_GITLEAKS", "/nonexistent/gitleaks")
    out = CliRunner().invoke(cli, ["sweep", "fs", "--opt", f"root={tree}", "--format", "json"]).output
    klasses = {f["klass"] for f in json.loads(out)["findings"]}
    assert "secret.git-remote-credential" in klasses
    assert any(k.startswith("perm.") for k in klasses)
