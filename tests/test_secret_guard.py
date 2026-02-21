"""Tests for SKSecurity SecretGuard module."""

import os
import tempfile
from pathlib import Path

import pytest

from sksecurity.secret_guard import SecretGuard, GuardResult, SecretFinding


@pytest.fixture
def guard():
    """Create a default SecretGuard instance."""
    return SecretGuard()


@pytest.fixture
def guard_with_allowlist():
    """Create a SecretGuard with allow patterns."""
    return SecretGuard(config={
        "secret_guard.allow_patterns": [r"EXAMPLE", r"test_token"],
    })


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


# ─── Expected Use: Text Scanning ─────────────────────────────────────


class TestTextScanning:
    """Verify secret detection in plain text."""

    def test_github_token_detected(self, guard):
        """GitHub personal access token should be found."""
        findings = guard.scan_text("token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn")
        assert len(findings) >= 1
        assert findings[0].secret_type == "GitHub Token"
        assert findings[0].severity == "CRITICAL"

    def test_aws_key_detected(self, guard):
        """AWS access key ID should be found."""
        findings = guard.scan_text("AWS_KEY=AKIAZ3BGHIJK7MNOPQRS")
        assert len(findings) >= 1
        assert findings[0].secret_type == "AWS Access Key"

    def test_npm_token_detected(self, guard):
        """npm access token should be found."""
        findings = guard.scan_text("npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn")
        assert len(findings) >= 1
        assert findings[0].secret_type == "npm Token"

    def test_private_key_detected(self, guard):
        """PEM private key should be found."""
        findings = guard.scan_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB...")
        assert len(findings) >= 1
        assert findings[0].secret_type == "Private Key"
        assert findings[0].severity == "CRITICAL"

    def test_stripe_key_detected(self, guard):
        """Stripe secret key should be found."""
        # Reason: construct dynamically to avoid triggering GitHub push protection
        prefix = "sk_" + "live" + "_"
        suffix = "A" * 30
        findings = guard.scan_text(f"STRIPE_KEY={prefix}{suffix}")
        assert len(findings) >= 1
        assert findings[0].secret_type == "Stripe Secret Key"

    def test_jwt_detected(self, guard):
        """JWT token should be found."""
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        findings = guard.scan_text(jwt)
        assert len(findings) >= 1
        assert findings[0].secret_type == "JWT Token"

    def test_clean_text_no_findings(self, guard):
        """Clean text should produce no findings."""
        findings = guard.scan_text(
            "This is a normal Python function:\ndef hello():\n    return 'world'"
        )
        assert len(findings) == 0

    def test_redaction(self, guard):
        """Matched secrets should be redacted."""
        findings = guard.scan_text("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn")
        assert len(findings) >= 1
        assert "ABCDEFGHIJ" not in findings[0].redacted_text
        assert "ghp_" in findings[0].redacted_text

    def test_remediation_provided(self, guard):
        """Findings should include remediation guidance."""
        findings = guard.scan_text("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn")
        assert len(findings) >= 1
        assert "Revoke" in findings[0].remediation


# ─── Expected Use: File Scanning ─────────────────────────────────────


class TestFileScanning:
    """Verify secret detection in files."""

    def test_scan_file_with_secret(self, guard, temp_dir):
        """File containing a secret should produce findings."""
        secret_file = temp_dir / "config.py"
        secret_file.write_text('API_KEY = "sk-abcdefghijklmnopqrstuvwxyz0123456789"\n')
        findings = guard.scan_file(secret_file)
        assert len(findings) >= 1

    def test_scan_clean_file(self, guard, temp_dir):
        """File without secrets should produce no findings."""
        clean_file = temp_dir / "clean.py"
        clean_file.write_text("def hello():\n    return 'world'\n")
        findings = guard.scan_file(clean_file)
        assert len(findings) == 0

    def test_skip_binary_extensions(self, guard, temp_dir):
        """Binary file extensions should be skipped."""
        binary = temp_dir / "image.png"
        binary.write_text("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn")
        findings = guard.scan_file(binary)
        assert len(findings) == 0

    def test_scan_directory(self, guard, temp_dir):
        """Directory scan should find secrets across multiple files."""
        (temp_dir / "good.py").write_text("x = 1\n")
        (temp_dir / "bad.py").write_text(
            'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"\n'
        )
        (temp_dir / "also_bad.env").write_text(
            "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLEQ\n"
        )
        result = guard.scan_directory(temp_dir)
        assert isinstance(result, GuardResult)
        assert result.has_secrets
        assert result.files_scanned >= 3

    def test_directory_skips_node_modules(self, guard, temp_dir):
        """node_modules directory should be skipped."""
        nm = temp_dir / "node_modules" / "evil-pkg"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text(
            'const key = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn";\n'
        )
        result = guard.scan_directory(temp_dir)
        assert not result.has_secrets


# ─── Guard Result ────────────────────────────────────────────────────


class TestGuardResult:
    """Verify GuardResult formatting and serialization."""

    def test_format_report_clean(self, guard, temp_dir):
        """Clean scan report should say 'No secrets'."""
        (temp_dir / "clean.py").write_text("x = 1\n")
        result = guard.scan_directory(temp_dir)
        report = result.format_report()
        assert "No secrets" in report

    def test_format_report_with_findings(self, guard, temp_dir):
        """Report with findings should list them."""
        (temp_dir / "bad.py").write_text(
            'k = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"\n'
        )
        result = guard.scan_directory(temp_dir)
        report = result.format_report()
        assert "GitHub Token" in report

    def test_to_dict(self, guard, temp_dir):
        """to_dict should produce a serializable dict."""
        (temp_dir / "test.py").write_text("pass\n")
        result = guard.scan_directory(temp_dir)
        data = result.to_dict()
        assert "target" in data
        assert "findings" in data
        assert "files_scanned" in data


# ─── Allow List ──────────────────────────────────────────────────────


class TestAllowList:
    """Verify allow list suppresses known-safe patterns."""

    def test_allowed_pattern_suppressed(self, guard_with_allowlist):
        """Patterns on the allow list should not produce findings."""
        findings = guard_with_allowlist.scan_text("AKIAIOSFODNN7EXAMPLE1")
        assert len(findings) == 0

    def test_non_allowed_still_detected(self, guard_with_allowlist):
        """Non-allowed secrets should still be detected."""
        findings = guard_with_allowlist.scan_text(
            "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"
        )
        assert len(findings) >= 1


# ─── Test Context Detection ──────────────────────────────────────────


class TestContextDetection:
    """Verify that test/example contexts are handled."""

    def test_example_context_suppressed(self, guard):
        """Secrets in example/test context should be suppressed."""
        findings = guard.scan_text(
            '# Example: AKIAIOSFODNN7EXAMPLEQ\n'
        )
        assert len(findings) == 0

    def test_real_context_not_suppressed(self, guard):
        """Secrets in production context should still be found."""
        findings = guard.scan_text(
            'production_key = "AKIAIOSFODNN7REALKEYQ"\n'
        )
        assert len(findings) >= 1


# ─── Edge Cases ──────────────────────────────────────────────────────


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_empty_text(self, guard):
        """Empty text should produce no findings."""
        findings = guard.scan_text("")
        assert len(findings) == 0

    def test_multiline_secret(self, guard):
        """Secret split across context should still be found."""
        text = "config = {\n  'key': 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn'\n}"
        findings = guard.scan_text(text)
        assert len(findings) >= 1

    def test_multiple_secrets_same_text(self, guard):
        """Multiple secrets in same text should all be found."""
        text = (
            "AWS=AKIAZ3BGHIJK7MNOPQRS\n"
            "GH=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn\n"
            "-----BEGIN RSA PRIVATE KEY-----\n"
        )
        findings = guard.scan_text(text)
        types = {f.secret_type for f in findings}
        assert "AWS Access Key" in types
        assert "GitHub Token" in types
        assert "Private Key" in types

    def test_nonexistent_file(self, guard):
        """Scanning a nonexistent file should return empty findings."""
        findings = guard.scan_file(Path("/nonexistent/path/to/file.py"))
        assert len(findings) == 0


# ─── Failure Cases ───────────────────────────────────────────────────


class TestFailureCases:
    """Ensure graceful handling of errors."""

    def test_unreadable_file(self, guard, temp_dir):
        """Unreadable file should not crash, returns empty findings."""
        bad_file = temp_dir / "unreadable.py"
        bad_file.write_text("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn")
        bad_file.chmod(0o000)
        try:
            findings = guard.scan_file(bad_file)
            assert isinstance(findings, list)
        finally:
            bad_file.chmod(0o644)

    def test_empty_directory(self, guard, temp_dir):
        """Empty directory should produce clean result."""
        result = guard.scan_directory(temp_dir)
        assert not result.has_secrets
        assert result.files_scanned == 0

    def test_scan_git_staged_no_repo(self, guard, temp_dir):
        """scan_git_staged on non-repo should return empty result."""
        result = guard.scan_git_staged(repo_path=temp_dir)
        assert isinstance(result, GuardResult)
        assert not result.has_secrets


# ─── Pre-commit Hook ─────────────────────────────────────────────────


class TestPreCommitHook:
    """Verify pre-commit hook generation."""

    def test_install_hook(self, guard, temp_dir):
        """Hook should be installed in .git/hooks/."""
        git_dir = temp_dir / ".git" / "hooks"
        git_dir.mkdir(parents=True)
        hook_path = guard.install_pre_commit_hook(temp_dir)
        assert hook_path.exists()
        assert os.access(hook_path, os.X_OK)
        content = hook_path.read_text()
        assert "sksecurity-secret-guard" in content

    def test_idempotent_install(self, guard, temp_dir):
        """Installing twice should not duplicate content."""
        git_dir = temp_dir / ".git" / "hooks"
        git_dir.mkdir(parents=True)
        guard.install_pre_commit_hook(temp_dir)
        guard.install_pre_commit_hook(temp_dir)
        content = (temp_dir / ".git" / "hooks" / "pre-commit").read_text()
        assert content.count("sksecurity-secret-guard") == 2  # BEGIN + END markers
