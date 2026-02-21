"""Tests for the ThreatIntelligence module."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from sksecurity.intelligence import ThreatIntelligence, ThreatSource, ThreatIndicator


class TestThreatSource:
    """Tests for the ThreatSource dataclass."""

    def test_disabled_source_returns_empty(self) -> None:
        """Disabled source returns empty list on fetch."""
        source = ThreatSource(name="test", url="http://example.com", enabled=False)
        assert source.fetch() == []

    def test_fetch_network_error(self) -> None:
        """Network failure returns empty list."""
        source = ThreatSource(name="bad", url="http://invalid.invalid.invalid")
        assert source.fetch() == []

    @patch("sksecurity.intelligence.requests.get")
    def test_fetch_success(self, mock_get: MagicMock) -> None:
        """Successful fetch returns parsed JSON."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = [{"type": "ip", "value": "1.2.3.4"}]
        mock_resp.text = '[{"type": "ip", "value": "1.2.3.4"}]'
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        source = ThreatSource(name="mock", url="http://example.com/feed")
        result = source.fetch()
        assert len(result) == 1
        assert source.last_fetch is not None


class TestThreatIndicator:
    """Tests for the ThreatIndicator dataclass."""

    def test_to_dict(self) -> None:
        """Indicator converts to dict correctly."""
        ind = ThreatIndicator(type="ip", value="10.0.0.1", severity="high", source="test")
        d = ind.to_dict()
        assert d["type"] == "ip"
        assert d["value"] == "10.0.0.1"
        assert d["severity"] == "high"
        assert "first_seen" in d

    def test_defaults(self) -> None:
        """Indicator has sensible defaults."""
        ind = ThreatIndicator(type="hash", value="abc123")
        assert ind.severity == "medium"
        assert ind.source == "unknown"
        assert ind.last_seen is None


class TestThreatIntelligence:
    """Tests for the ThreatIntelligence class."""

    def test_default_sources(self) -> None:
        """Default sources are loaded when none provided."""
        ti = ThreatIntelligence()
        assert len(ti.sources) >= 2

    def test_custom_sources(self) -> None:
        """Custom sources override defaults."""
        ti = ThreatIntelligence(sources=[
            {"name": "custom", "url": "http://example.com", "enabled": True, "priority": 1}
        ])
        assert len(ti.sources) == 1
        assert ti.sources[0].name == "custom"

    def test_config_sources(self) -> None:
        """Sources from config dict are used when no explicit sources."""
        ti = ThreatIntelligence(config={
            "threat_sources": [
                {"name": "from_config", "url": "http://x.com", "enabled": True}
            ]
        })
        assert ti.sources[0].name == "from_config"

    def test_add_custom_threat(self) -> None:
        """Custom threats can be added."""
        ti = ThreatIntelligence(sources=[])
        ind = ThreatIndicator(type="ip", value="evil.example.com")
        ti.add_custom_threat(ind)
        assert ti.is_threat("evil.example.com")

    def test_check_returns_indicator(self) -> None:
        """check() returns the indicator for known threats."""
        ti = ThreatIntelligence(sources=[])
        ind = ThreatIndicator(type="hash", value="deadbeef", severity="critical")
        ti.add_custom_threat(ind)
        result = ti.check("deadbeef")
        assert result is not None
        assert result.severity == "critical"

    def test_check_returns_none_for_unknown(self) -> None:
        """check() returns None for unknown values."""
        ti = ThreatIntelligence(sources=[])
        assert ti.check("unknown_value") is None

    def test_is_threat(self) -> None:
        """is_threat() returns boolean."""
        ti = ThreatIntelligence(sources=[])
        ind = ThreatIndicator(type="ip", value="bad_ip")
        ti.add_custom_threat(ind)
        assert ti.is_threat("bad_ip") is True
        assert ti.is_threat("good_ip") is False

    def test_get_threats_all(self) -> None:
        """get_threats() returns all indicators."""
        ti = ThreatIntelligence(sources=[])
        ti.add_custom_threat(ThreatIndicator(type="ip", value="a", severity="high"))
        ti.add_custom_threat(ThreatIndicator(type="ip", value="b", severity="low"))
        assert len(ti.get_threats()) == 2

    def test_get_threats_by_severity(self) -> None:
        """get_threats() filters by severity."""
        ti = ThreatIntelligence(sources=[])
        ti.add_custom_threat(ThreatIndicator(type="ip", value="a", severity="high"))
        ti.add_custom_threat(ThreatIndicator(type="ip", value="b", severity="low"))
        assert len(ti.get_threats(severity="high")) == 1

    def test_builtin_patterns(self) -> None:
        """Built-in patterns are included."""
        ti = ThreatIntelligence(sources=[])
        patterns = ti.get_patterns()
        assert len(patterns) > 0
        types = {p["type"] for p in patterns}
        assert "code_injection" in types
        assert "hardcoded_secrets" in types

    def test_indicators_as_patterns(self) -> None:
        """Signature indicators become scanner patterns."""
        ti = ThreatIntelligence(sources=[])
        ti.add_custom_threat(ThreatIndicator(
            type="signature", value=r"malware_pattern_\d+", severity="critical"
        ))
        patterns = ti.get_patterns()
        sig_patterns = [p for p in patterns if p["source"] != "builtin"]
        assert len(sig_patterns) == 1

    def test_get_status(self) -> None:
        """get_status() returns summary dict."""
        ti = ThreatIntelligence(sources=[])
        status = ti.get_status()
        assert "total_patterns" in status
        assert "last_update" in status
        assert "sources" in status

    def test_export(self, tmp_path: Path) -> None:
        """Indicators can be exported to JSON."""
        ti = ThreatIntelligence(sources=[])
        ti.add_custom_threat(ThreatIndicator(type="ip", value="1.2.3.4"))
        export_path = str(tmp_path / "export.json")
        ti.export(export_path)

        with open(export_path) as f:
            data = json.load(f)
        assert "1.2.3.4" in data["indicators"]

    @patch("sksecurity.intelligence.requests.get")
    def test_update_adds_indicators(self, mock_get: MagicMock) -> None:
        """update() fetches and adds new indicators."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = [
            {"type": "ip", "value": "5.6.7.8", "severity": "high"},
        ]
        mock_resp.text = "ok"
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        ti = ThreatIntelligence(sources=[
            {"name": "mock", "url": "http://example.com", "enabled": True}
        ])
        new_count = ti.update()
        assert new_count == 1
        assert ti.is_threat("5.6.7.8")
