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
        for cmd in ["scan", "dashboard", "update", "monitor", "init",
                     "quarantine", "audit", "status", "screen"]:
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

    def test_config_option_exists(self, runner):
        """--config option is accepted."""
        result = runner.invoke(cli, ["--help"])
        assert "--config" in result.output

    def test_verbose_option_exists(self, runner):
        """--verbose option is accepted."""
        result = runner.invoke(cli, ["--help"])
        assert "--verbose" in result.output


class TestScanIsReportOnly:
    """`scan` must never move, delete or modify the scanned files."""

    def _risky_tree(self, root):
        (root / "pkg").mkdir()
        files = {
            root / "pkg" / "a.py": "import os\nos.system('rm -rf /')\neval(input())\n",
            root / "pkg" / "b.py": "import pickle\npickle.loads(x)\n",
            root / "notes.txt": "AKIAIOSFODNN7EXAMPLE\n",
        }
        for p, body in files.items():
            p.write_text(body)
        return files

    def test_scan_above_threshold_leaves_files_in_place(self, runner, tmp_path, monkeypatch):
        from sksecurity.quarantine import QuarantineManager

        def boom(*a, **k):
            raise AssertionError("scan must not quarantine")

        monkeypatch.setattr(QuarantineManager, "quarantine", boom)
        tree = tmp_path / "target"
        tree.mkdir()
        files = self._risky_tree(tree)
        before = {p: p.read_text() for p in files}

        # Threshold 0 means every run is "above threshold".
        runner.invoke(cli, ["scan", str(tree), "--threshold", "0"])

        assert tree.is_dir()
        for p, body in before.items():
            assert p.exists(), f"{p} was moved or deleted"
            assert p.read_text() == body

    def test_scan_has_no_quarantine_option(self, runner):
        result = runner.invoke(cli, ["scan", "--help"])
        assert "--quarantine" not in result.output
