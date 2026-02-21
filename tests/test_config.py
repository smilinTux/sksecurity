"""Tests for the SecurityConfig module."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
import yaml

from sksecurity.config import SecurityConfig, SecurityPolicy


class TestSecurityPolicy:
    """Tests for the SecurityPolicy dataclass."""

    def test_defaults(self) -> None:
        """Policy has sensible defaults."""
        policy = SecurityPolicy(name="test")
        assert policy.enabled is True
        assert policy.auto_quarantine is False
        assert policy.scan_depth == 3

    def test_to_dict(self) -> None:
        """Policy converts to dict."""
        policy = SecurityPolicy(name="strict", auto_quarantine=True, scan_depth=5)
        d = policy.to_dict()
        assert d["name"] == "strict"
        assert d["auto_quarantine"] is True
        assert d["scan_depth"] == 5

    def test_custom_extensions(self) -> None:
        """Policy accepts custom file extensions."""
        policy = SecurityPolicy(name="custom", file_extensions=[".rs", ".go"])
        assert ".rs" in policy.file_extensions


class TestSecurityConfig:
    """Tests for the SecurityConfig class."""

    def test_default_config(self, tmp_path: Path) -> None:
        """Config loads defaults when no file exists."""
        config = SecurityConfig(config_path=str(tmp_path / "nonexistent.yaml"))
        assert config.enabled is True
        assert config.dashboard_port == 8888

    def test_load_yaml_config(self, tmp_path: Path) -> None:
        """Config loads from YAML file."""
        config_data = {
            "security": {"enabled": False, "risk_threshold": 50, "dashboard_port": 9999},
            "scanning": {"default_depth": 5},
            "monitoring": {"runtime_monitoring": False},
        }
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump(config_data), encoding="utf-8")

        config = SecurityConfig(config_path=str(config_file))
        assert config.enabled is False
        assert config.risk_threshold == 50
        assert config.dashboard_port == 9999

    def test_load_json_config(self, tmp_path: Path) -> None:
        """Config loads from JSON file."""
        config_data = {
            "security": {"enabled": True, "risk_threshold": 90},
            "scanning": {"default_depth": 2},
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data), encoding="utf-8")

        config = SecurityConfig(config_path=str(config_file))
        assert config.risk_threshold == 90

    def test_dot_notation_get(self, tmp_path: Path) -> None:
        """get() supports dot notation for nested keys."""
        config = SecurityConfig(config_path=str(tmp_path / "none.yaml"))
        assert config.get("security.enabled") is True
        assert config.get("nonexistent.key", "fallback") == "fallback"

    def test_dot_notation_set(self, tmp_path: Path) -> None:
        """set() supports dot notation for nested keys."""
        config_file = tmp_path / "config.yaml"
        config = SecurityConfig(config_path=str(config_file))
        config.set("security.risk_threshold", 42)
        assert config.get("security.risk_threshold") == 42

    def test_save_creates_file(self, tmp_path: Path) -> None:
        """save() creates the config file."""
        config_file = tmp_path / "sub" / "config.yaml"
        config = SecurityConfig(config_path=str(config_file))
        config.save()
        assert config_file.exists()

    def test_add_and_list_policies(self, tmp_path: Path) -> None:
        """Policies can be added and listed."""
        config = SecurityConfig(config_path=str(tmp_path / "c.yaml"))
        policy = SecurityPolicy(name="strict", auto_quarantine=True)
        config.add_policy(policy)

        policies = config.list_policies()
        assert len(policies) == 1
        assert policies[0].name == "strict"

    def test_remove_policy(self, tmp_path: Path) -> None:
        """Policies can be removed."""
        config = SecurityConfig(config_path=str(tmp_path / "c.yaml"))
        config.add_policy(SecurityPolicy(name="temp"))
        assert config.remove_policy("temp") is True
        assert config.remove_policy("nonexistent") is False

    def test_get_policy(self, tmp_path: Path) -> None:
        """Individual policy can be retrieved by name."""
        config = SecurityConfig(config_path=str(tmp_path / "c.yaml"))
        config.add_policy(SecurityPolicy(name="prod", scan_depth=10))
        p = config.get_policy("prod")
        assert p is not None
        assert p.scan_depth == 10
        assert config.get_policy("nope") is None

    def test_threat_sources(self, tmp_path: Path) -> None:
        """Threat sources can be added and retrieved."""
        config = SecurityConfig(config_path=str(tmp_path / "c.yaml"))
        config.add_threat_source({"name": "Custom", "url": "https://example.com"})
        sources = config.get_threat_sources()
        assert any(s["name"] == "Custom" for s in sources)

    def test_properties(self, tmp_path: Path) -> None:
        """Property accessors return correct values."""
        config = SecurityConfig(config_path=str(tmp_path / "c.yaml"))
        assert isinstance(config.default_depth, int)
        assert isinstance(config.extensions, list)
        assert isinstance(config.runtime_monitoring, bool)
        assert isinstance(config.file_system_monitoring, bool)
        assert isinstance(config.auto_quarantine, bool)

    def test_to_dict(self, tmp_path: Path) -> None:
        """to_dict returns the full config."""
        config = SecurityConfig(config_path=str(tmp_path / "c.yaml"))
        d = config.to_dict()
        assert "security" in d
        assert "scanning" in d

    def test_corrupt_config_falls_back(self, tmp_path: Path) -> None:
        """Corrupt config file falls back to defaults."""
        config_file = tmp_path / "bad.yaml"
        config_file.write_text("{{{invalid yaml", encoding="utf-8")
        config = SecurityConfig(config_path=str(config_file))
        assert config.enabled is True
