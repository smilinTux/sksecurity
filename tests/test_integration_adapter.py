"""Dual/tri-mode tests for the sksecurity ⇄ skcapstone integration adapter.

Contract per skcapstone/docs/ADR-optional-integration-backbone.md:
  * standalone (SK_STANDALONE=1) / absent (no skcapstone) → native fallback
  * integrated (skcapstone present) → sk-alert / skscheduler / registry

skcapstone is installed in the dev venv, so "integrated" mode is exercised
against a sandboxed temp SKCAPSTONE_HOME.
"""

from __future__ import annotations

import json

import pytest

from sksecurity import integration


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Sandbox skcapstone's shared home at a temp dir for this test."""
    monkeypatch.setenv("SKCAPSTONE_HOME", str(tmp_path))
    monkeypatch.delenv("SK_STANDALONE", raising=False)
    import skcapstone

    monkeypatch.setattr(skcapstone, "AGENT_HOME", str(tmp_path))
    return tmp_path


# -- severity mapping -------------------------------------------------------

def test_severity_mapping():
    assert integration.level_for_severity("critical") == "critical"
    assert integration.level_for_severity("high") == "error"
    assert integration.level_for_severity("medium") == "warn"
    assert integration.level_for_severity("low") == "info"
    assert integration.level_for_severity("unknown") == "warn"


# -- standalone / absent ----------------------------------------------------

def test_standalone_disables_integration(monkeypatch):
    monkeypatch.setenv("SK_STANDALONE", "1")
    assert integration.is_present() is False
    assert integration.alert("process", {"m": 1}, level="error") is False
    assert integration.ensure_schedule() is False
    assert integration.register_self() is False


def test_absent_skcapstone_falls_back(monkeypatch):
    monkeypatch.delenv("SK_STANDALONE", raising=False)
    monkeypatch.setattr(integration, "_sdk", None)
    assert integration.is_present() is False
    assert integration.alert("secret_leak", {"file": "x"}, level="critical") is False


# -- integrated -------------------------------------------------------------

def test_alert_publishes_severity_topic(home):
    assert integration.is_present() is True
    assert integration.alert("secret_leak", {"file": "id_rsa"}, level="critical") is True
    topic_dir = home / "pubsub" / "topics" / "sksecurity.critical"
    assert topic_dir.is_dir()
    data = json.loads(next(topic_dir.glob("msg-*.json")).read_text())
    assert data["topic"] == "sksecurity.critical"
    assert data["payload"]["event"] == "secret_leak"
    assert data["payload"]["file"] == "id_rsa"


def test_ensure_schedule_registers_intel_refresh(home):
    assert integration.ensure_schedule(interval_hours=24) is True
    from skcapstone.scheduler_jobs import load_jobs_with_dropins

    jobs = {j.name: j for j in load_jobs_with_dropins(home / "config" / "jobs.yaml")}
    assert "sksecurity_intel_refresh" in jobs
    assert jobs["sksecurity_intel_refresh"].command == "sksecurity update --sources all"
    assert jobs["sksecurity_intel_refresh"].every_seconds == 24 * 3600
    assert integration.unregister_schedule() is True


def test_register_self_writes_registry(home):
    assert integration.register_self(pid_file="/tmp/sksec.pid") is True
    entry = json.loads((home / "registry" / "sksecurity.json").read_text())
    assert entry["name"] == "sksecurity"


# -- end-to-end: SecurityMonitor event → shared bus -------------------------

class _StubConfig:
    runtime_monitoring = False

    def get(self, key, default=None):
        return default


def test_monitor_event_shares_threat(home):
    from sksecurity.monitor import SecurityMonitor, MonitorEvent

    mon = SecurityMonitor(_StubConfig())
    mon._on_event(MonitorEvent(
        type="process", severity="high",
        message="High CPU usage: 99%", details={"cpu_percent": 99},
    ))
    # high → error topic
    topic_dir = home / "pubsub" / "topics" / "sksecurity.error"
    assert topic_dir.is_dir()
    data = json.loads(next(topic_dir.glob("msg-*.json")).read_text())
    assert data["payload"]["event"] == "process"
    assert data["payload"]["severity"] == "high"
    assert data["payload"]["cpu_percent"] == 99
