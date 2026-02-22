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
