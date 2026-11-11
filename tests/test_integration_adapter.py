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
    # skcapstone is a sovereign sibling, not on PyPI: skip on public runners.
    skcapstone = pytest.importorskip("skcapstone")

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


def test_no_registration_or_scheduler_api():
    """The adapter must not register the service or write scheduler jobs."""
    for name in ("register_self", "ensure_schedule", "unregister_schedule"):
        assert not hasattr(integration, name)
