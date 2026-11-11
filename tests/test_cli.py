"""Tests for the SKSecurity CLI."""

import pytest
from click.testing import CliRunner

from sksecurity import __version__
from sksecurity.cli import cli


@pytest.fixture
def runner():
    """Create a CLI test runner."""
    return CliRunner()


class TestCLIVersion:
    """Version flag consistency tests."""

    def test_version_flag(self, runner):
        """--version prints version string with prog name."""
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "sksecurity" in result.output
        assert __version__ in result.output

    def test_version_flag_format(self, runner):
        """Version output follows 'prog_name, version X.Y.Z' pattern."""
        result = runner.invoke(cli, ["--version"])
        assert f"sksecurity, version {__version__}" in result.output


class TestCLIHelp:
    """Help text tests."""

    def test_help_flag(self, runner):
        """--help shows usage information."""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "SKSecurity" in result.output

    def test_subcommand_help(self, runner):
        """Subcommands have help text."""
        for cmd in ["screen", "pqc-report", "pqc-posture", "pqc-stacks",
                    "pqc-snapshot", "pqc-dashboard"]:
            result = runner.invoke(cli, [cmd, "--help"])
            assert result.exit_code == 0, f"{cmd} --help failed"

    def test_guard_subgroup_help(self, runner):
        """Guard subgroup and subcommands have help text."""
        result = runner.invoke(cli, ["guard", "--help"])
        assert result.exit_code == 0

        for cmd in ["scan", "staged", "install", "text"]:
            result = runner.invoke(cli, ["guard", cmd, "--help"])
            assert result.exit_code == 0, f"guard {cmd} --help failed"


class TestCLIGlobalOptions:
    """Global option tests."""

    def test_verbose_option_exists(self, runner):
        """--verbose option is accepted."""
        result = runner.invoke(cli, ["--help"])
        assert "--verbose" in result.output


class TestRemovedCommands:
    """The 2.0 refactor removed the SOC shell, including the move-the-tree
    quarantine behaviour. These must stay gone."""

    @pytest.mark.parametrize("cmd", [
        "scan", "audit", "quarantine", "status", "update",
        "monitor", "dashboard", "init",
    ])
    def test_command_removed(self, runner, cmd):
        result = runner.invoke(cli, [cmd, "--help"])
        assert result.exit_code != 0

    @pytest.mark.parametrize("opt", ["--ai", "--ai-model", "--ai-url", "--config"])
    def test_option_removed(self, runner, opt):
        result = runner.invoke(cli, ["--help"])
        assert opt not in result.output

    def test_kept_commands_listed(self, runner):
        out = runner.invoke(cli, ["--help"]).output
        for cmd in ["guard", "claims", "screen", "pqc-report", "pqc-posture"]:
            assert cmd in out


class TestNothingIsMoved:
    """No kept command may move, delete or modify the files it inspects."""

    def _tree(self, root):
        root.mkdir()
        files = {
            root / "a.py": "import os\nos.system('rm -rf /')\nkey = 'AKIAIOSFODNN7EXAMPLE'\n",
            root / "notes.txt": "password = 'hunter2hunter2'\n",
        }
        for p, body in files.items():
            p.write_text(body)
        return files

    def test_guard_scan_leaves_files_in_place(self, runner, tmp_path):
        tree = tmp_path / "target"
        files = self._tree(tree)
        before = {p: p.read_text() for p in files}
        result = runner.invoke(cli, ["guard", "scan", str(tree)])
        assert result.exit_code == 1  # secrets found
        for p, body in before.items():
            assert p.exists() and p.read_text() == body

    def test_claims_scan_leaves_files_in_place(self, runner, tmp_path):
        tree = tmp_path / "docs"
        tree.mkdir()
        f = tree / "x.md"
        f.write_text("This is quantum-proof.\n")  # honest-claims: allow
        result = runner.invoke(cli, ["claims", "scan", str(tree)])
        assert result.exit_code == 1
        assert f.read_text() == "This is quantum-proof.\n"  # honest-claims: allow


class TestKeptCommandsWork:
    def test_guard_text_finds_secret(self, runner):
        r = runner.invoke(cli, ["guard", "text", "api_key=" + "sk-" + "abc123456789012345678901234567890123"])
        assert r.exit_code == 1

    def test_guard_text_clean(self, runner):
        r = runner.invoke(cli, ["guard", "text", "hello world"])
        assert r.exit_code == 0

    def test_claims_text_clean(self, runner):
        r = runner.invoke(cli, ["claims", "text", "we never say quantum-proof"])
        assert r.exit_code == 0

    def test_screen_json(self, runner):
        r = runner.invoke(cli, ["screen", "hello there", "--format", "json"])
        assert r.exit_code == 0
        assert "verdict" in r.output.lower()


def test_sweep_baseline_flag_writes_baseline_and_silences_exit(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from sksecurity import cli as cli_mod, sweeps
    from sksecurity.findings import Finding

    monkeypatch.setenv("SKSECURITY_STATE_DIR", str(tmp_path))
    f = Finding("fs", "secret.tracked-env", "high", "/x/.env", "s", "fp1")
    monkeypatch.setattr(sweeps, "get", lambda name: (lambda **kw: [f]))
    runner = CliRunner()
    assert runner.invoke(cli_mod.cli, ["sweep", "fs"]).exit_code == 1
    res = runner.invoke(cli_mod.cli, ["sweep", "fs", "--baseline"])
    assert res.exit_code == 0 and (tmp_path / "baseline-fs.json").is_file()
    assert runner.invoke(cli_mod.cli, ["sweep", "fs"]).exit_code == 0  # accepted now
