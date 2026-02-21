"""Tests for the SecurityScanner module."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from sksecurity.scanner import SecurityScanner, ScanResult, ThreatMatch


@pytest.fixture
def scanner() -> SecurityScanner:
    """Create a scanner with no database connection."""
    return SecurityScanner(config={})


@pytest.fixture
def safe_dir(tmp_path: Path) -> Path:
    """Create a temp directory with safe files."""
    (tmp_path / "hello.py").write_text("print('hello world')\n", encoding="utf-8")
    (tmp_path / "readme.md").write_text("# My Project\n", encoding="utf-8")
    return tmp_path


@pytest.fixture
def dangerous_dir(tmp_path: Path) -> Path:
    """Create a temp directory with files containing threat patterns."""
    (tmp_path / "bad.py").write_text(
        "import os\nresult = eval(user_input)\nos.system('rm -rf /')\n",
        encoding="utf-8",
    )
    (tmp_path / "secrets.py").write_text(
        'password = "SuperSecret1234567890"\napi_key = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"\n',
        encoding="utf-8",
    )
    return tmp_path


class TestScanResult:
    """Tests for the ScanResult dataclass."""

    def test_to_dict(self) -> None:
        """ScanResult converts to dict."""
        result = ScanResult(
            target_path="/tmp/test",
            scan_timestamp="2026-02-21T00:00:00",
            risk_score=0.0,
            threat_count=0,
            files_scanned=1,
            threats=[],
            recommendations=[],
            summary="Clean",
        )
        d = result.to_dict()
        assert d["target_path"] == "/tmp/test"
        assert d["risk_score"] == 0.0

    def test_to_json(self) -> None:
        """ScanResult converts to JSON."""
        result = ScanResult(
            target_path="/tmp/test",
            scan_timestamp="2026-02-21T00:00:00",
            risk_score=50.0,
            threat_count=2,
            files_scanned=10,
            threats=[],
            recommendations=["Review code"],
            summary="Medium risk",
        )
        json_str = result.to_json()
        assert '"risk_score": 50.0' in json_str

    def test_format_report_clean(self) -> None:
        """Clean scan report formats correctly."""
        result = ScanResult(
            target_path="/tmp/clean",
            scan_timestamp="2026-02-21T00:00:00",
            risk_score=0.0,
            threat_count=0,
            files_scanned=5,
            threats=[],
            recommendations=["Standard monitoring sufficient"],
            summary="No threats",
        )
        report = result.format_report()
        assert "No security threats detected" in report
        assert "LOW RISK" in report

    def test_format_report_threats(self) -> None:
        """Report with threats includes severity grouping."""
        threat = ThreatMatch(
            threat_type="code_injection",
            severity="CRITICAL",
            confidence=0.9,
            file_path="/tmp/bad.py",
            line_number=1,
            pattern="eval",
            context="eval(user_input)",
        )
        result = ScanResult(
            target_path="/tmp/bad",
            scan_timestamp="2026-02-21T00:00:00",
            risk_score=85.0,
            threat_count=1,
            files_scanned=1,
            threats=[threat],
            recommendations=["Quarantine"],
            summary="Critical risk",
        )
        report = result.format_report()
        assert "CRITICAL" in report
        assert "code_injection" in report


class TestSecurityScanner:
    """Tests for the SecurityScanner class."""

    def test_scan_safe_directory(self, scanner: SecurityScanner, safe_dir: Path) -> None:
        """Scanning safe files produces low risk score."""
        result = scanner.scan(safe_dir)
        assert isinstance(result, ScanResult)
        assert result.files_scanned >= 1
        assert result.risk_score < 60

    def test_scan_dangerous_directory(self, scanner: SecurityScanner, dangerous_dir: Path) -> None:
        """Scanning dangerous files produces higher risk score."""
        result = scanner.scan(dangerous_dir)
        assert result.threat_count > 0
        assert result.risk_score > 0

    def test_scan_single_file(self, scanner: SecurityScanner, safe_dir: Path) -> None:
        """Scanning a single file works."""
        result = scanner.scan(safe_dir / "hello.py")
        assert result.files_scanned == 1

    def test_scan_nonexistent_raises(self, scanner: SecurityScanner) -> None:
        """Scanning nonexistent path raises ValueError."""
        with pytest.raises(ValueError, match="does not exist"):
            scanner.scan("/nonexistent/path/xyz")

    def test_recommendations_generated(self, scanner: SecurityScanner, dangerous_dir: Path) -> None:
        """Recommendations are generated for scans with threats."""
        result = scanner.scan(dangerous_dir)
        assert len(result.recommendations) > 0

    def test_summary_generated(self, scanner: SecurityScanner, safe_dir: Path) -> None:
        """Summary is always generated."""
        result = scanner.scan(safe_dir)
        assert result.summary != ""

    def test_skips_binary_extensions(self, scanner: SecurityScanner, tmp_path: Path) -> None:
        """Binary file extensions are skipped."""
        (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n")
        (tmp_path / "code.py").write_text("x = 1\n", encoding="utf-8")
        result = scanner.scan(tmp_path)
        assert result.files_scanned == 1

    def test_skips_large_files(self, tmp_path: Path) -> None:
        """Files exceeding max size are skipped."""
        small_scanner = SecurityScanner()
        small_scanner.max_file_size = 100
        (tmp_path / "big.py").write_text("x = 1\n" * 1000, encoding="utf-8")
        (tmp_path / "small.py").write_text("y = 2\n", encoding="utf-8")
        result = small_scanner.scan(tmp_path)
        assert result.files_scanned == 1

    def test_risk_score_bounds(self, scanner: SecurityScanner, dangerous_dir: Path) -> None:
        """Risk score stays within 0-100."""
        result = scanner.scan(dangerous_dir)
        assert 0.0 <= result.risk_score <= 100.0

    def test_empty_directory(self, scanner: SecurityScanner, tmp_path: Path) -> None:
        """Empty directory scans cleanly."""
        result = scanner.scan(tmp_path)
        assert result.files_scanned == 0
        assert result.risk_score == 0.0


class TestHeuristics:
    """Tests for heuristic analysis methods."""

    def test_documentation_context_detected(self, scanner: SecurityScanner) -> None:
        """Lines that are clearly documentation are skipped."""
        assert scanner._is_documentation_context("# example: eval(something)")
        assert scanner._is_documentation_context("// example of eval usage")
        assert not scanner._is_documentation_context("result = eval(user_input)")

    def test_entropy_calculation(self, scanner: SecurityScanner) -> None:
        """Entropy calculation returns reasonable values."""
        low_entropy = scanner._calculate_entropy("aaaaaaaaaa")
        high_entropy = scanner._calculate_entropy(
            "aB3$xZ9@qW5!mK7#pL2&nJ4*rT6^"
        )
        assert low_entropy < high_entropy

    def test_risk_score_empty(self, scanner: SecurityScanner) -> None:
        """No threats yields zero risk."""
        score = scanner._calculate_risk_score([])
        assert score == 0.0

    def test_risk_score_critical(self, scanner: SecurityScanner) -> None:
        """Critical threats yield higher score than low threats."""
        critical = ThreatMatch(
            threat_type="injection", severity="CRITICAL",
            confidence=1.0, file_path="x", line_number=1,
            pattern="x", context="x"
        )
        low = ThreatMatch(
            threat_type="minor", severity="LOW",
            confidence=1.0, file_path="x", line_number=1,
            pattern="x", context="x"
        )
        score_critical = scanner._calculate_risk_score([critical])
        score_low = scanner._calculate_risk_score([low])
        assert score_critical > score_low
