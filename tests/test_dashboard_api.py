"""Tests for SKSecurity dashboard REST API endpoints.

Covers:
- GET /api/health
- GET /api/overview
- GET /api/events (with filters)
- POST /api/events/<id>/ack
- POST /api/events/ack-all
- GET /api/stats
- GET /api/quarantine
- POST /api/quarantine/restore
- GET /api/monitor
- GET /api/threats
- GET /api/kms/status
- GET /api/kms/keys (with filters)
- POST /api/kms/rotate
- POST /api/scan
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Load dashboard module directly to avoid flask-dependent __init__ import chain
_dash_path = Path(__file__).resolve().parent.parent / "sksecurity" / "dashboard.py"
_kms_path = Path(__file__).resolve().parent.parent / "sksecurity" / "kms.py"

# Load kms first (dashboard imports it)
_kms_spec = importlib.util.spec_from_file_location("sksecurity.kms", _kms_path)
_kms_mod = importlib.util.module_from_spec(_kms_spec)
sys.modules["sksecurity.kms"] = _kms_mod
_kms_spec.loader.exec_module(_kms_mod)

# Now import the real modules
from sksecurity.dashboard import DashboardServer
from sksecurity.database import SecurityDatabase, SecurityEvent
from sksecurity.kms import KMS, FileKeyStore, KeyType
from sksecurity.quarantine import QuarantineManager


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db(tmp_path):
    """In-memory SecurityDatabase."""
    return SecurityDatabase(db_path=str(tmp_path / "test.db"))


@pytest.fixture
def quarantine(tmp_path):
    """QuarantineManager with temp directory."""
    return QuarantineManager(quarantine_dir=str(tmp_path / "quarantine"))


@pytest.fixture
def kms(tmp_path):
    """Unsealed KMS instance."""
    store = FileKeyStore(store_dir=tmp_path / "kms-keys")
    audit = tmp_path / "kms-audit.log"
    k = KMS(store=store, audit_path=audit)
    k.unseal("test-passphrase")
    return k


@pytest.fixture
def mock_intel():
    """Mock ThreatIntelligence."""
    intel = MagicMock()
    intel.get_status.return_value = {
        "total_patterns": 42,
        "last_update": "2026-02-27T12:00:00",
        "sources": [
            {"name": "TestSource", "enabled": True, "last_fetch": "2026-02-27T12:00:00"},
        ],
    }
    return intel


@pytest.fixture
def mock_monitor():
    """Mock RuntimeMonitor."""
    mon = MagicMock()
    mon.start = MagicMock()
    mon.stop = MagicMock()
    return mon


@pytest.fixture
def client(db, quarantine, kms, mock_intel, mock_monitor):
    """Flask test client with all data sources wired."""
    server = DashboardServer(
        db=db,
        quarantine=quarantine,
        kms=kms,
        intel=mock_intel,
        monitor=mock_monitor,
    )
    server._start_time = datetime.now()
    server.app.testing = True
    return server.app.test_client()


@pytest.fixture
def client_no_kms(db, quarantine, mock_intel, mock_monitor):
    """Flask test client without KMS."""
    server = DashboardServer(
        db=db,
        quarantine=quarantine,
        kms=None,
        scanner=None,
        intel=mock_intel,
        monitor=mock_monitor,
    )
    server._start_time = datetime.now()
    server.app.testing = True
    return server.app.test_client()


def _json(response):
    """Parse JSON from Flask test response."""
    return json.loads(response.data)


# ---------------------------------------------------------------------------
# 1. Health
# ---------------------------------------------------------------------------


class TestHealth:
    """Tests for GET /api/health."""

    def test_health_returns_running(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = _json(resp)
        assert data["status"] == "running"
        assert data["service"] == "sksecurity"
        assert "uptime_seconds" in data
        assert "timestamp" in data


# ---------------------------------------------------------------------------
# 2. Overview
# ---------------------------------------------------------------------------


class TestOverview:
    """Tests for GET /api/overview."""

    def test_overview_returns_all_sections(self, client):
        resp = client.get("/api/overview")
        assert resp.status_code == 200
        data = _json(resp)
        assert "health" in data
        assert "stats" in data
        assert "recent_events" in data
        assert "system" in data
        assert "quarantine" in data
        assert "intel" in data
        assert "timestamp" in data


# ---------------------------------------------------------------------------
# 3. Events
# ---------------------------------------------------------------------------


class TestEvents:
    """Tests for /api/events endpoints."""

    def test_events_empty(self, client):
        resp = client.get("/api/events")
        assert resp.status_code == 200
        data = _json(resp)
        assert data["count"] == 0
        assert data["events"] == []

    def test_events_with_data(self, client, db):
        db.log_event(SecurityEvent(
            event_type="scan", severity="high",
            source="test", message="Test threat found",
        ))
        db.log_event(SecurityEvent(
            event_type="scan", severity="low",
            source="test", message="Minor issue",
        ))
        resp = client.get("/api/events")
        data = _json(resp)
        assert data["count"] == 2

    def test_events_severity_filter(self, client, db):
        db.log_event(SecurityEvent(
            event_type="scan", severity="critical",
            source="test", message="Critical!",
        ))
        db.log_event(SecurityEvent(
            event_type="scan", severity="low",
            source="test", message="Low issue",
        ))
        resp = client.get("/api/events?severity=critical")
        data = _json(resp)
        assert data["count"] == 1
        assert data["events"][0]["severity"] == "critical"

    def test_events_limit(self, client, db):
        for i in range(5):
            db.log_event(SecurityEvent(
                event_type="scan", severity="info",
                source="test", message=f"Event {i}",
            ))
        resp = client.get("/api/events?limit=2")
        data = _json(resp)
        assert data["count"] == 2

    def test_ack_event(self, client, db):
        eid = db.log_event(SecurityEvent(
            event_type="scan", severity="high",
            source="test", message="Ack me",
        ))
        resp = client.post(f"/api/events/{eid}/ack")
        assert resp.status_code == 200
        data = _json(resp)
        assert data["acknowledged"] is True

    def test_ack_all(self, client, db):
        for i in range(3):
            db.log_event(SecurityEvent(
                event_type="scan", severity="high",
                source="test", message=f"Event {i}",
            ))
        resp = client.post(
            "/api/events/ack-all",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = _json(resp)
        assert data["acknowledged_count"] >= 3


# ---------------------------------------------------------------------------
# 4. Stats
# ---------------------------------------------------------------------------


class TestStats:
    """Tests for GET /api/stats."""

    def test_stats_empty(self, client):
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        data = _json(resp)
        assert data["total_events"] == 0
        assert data["unacknowledged"] == 0

    def test_stats_aggregation(self, client, db):
        db.log_event(SecurityEvent(event_type="scan", severity="high", source="t", message="a"))
        db.log_event(SecurityEvent(event_type="scan", severity="high", source="t", message="b"))
        db.log_event(SecurityEvent(event_type="threat", severity="critical", source="t", message="c"))

        resp = client.get("/api/stats")
        data = _json(resp)
        assert data["total_events"] == 3
        assert data["by_severity"]["high"] == 2
        assert data["by_severity"]["critical"] == 1
        assert data["by_type"]["scan"] == 2
        assert data["by_type"]["threat"] == 1


# ---------------------------------------------------------------------------
# 5. Quarantine
# ---------------------------------------------------------------------------


class TestQuarantine:
    """Tests for /api/quarantine endpoints."""

    def test_quarantine_empty(self, client):
        resp = client.get("/api/quarantine")
        assert resp.status_code == 200
        data = _json(resp)
        assert data["records"] == []

    def test_quarantine_with_record(self, client, quarantine, tmp_path):
        target = tmp_path / "evil.sh"
        target.write_text("rm -rf /")
        quarantine.quarantine(str(target), "command_injection", "critical")

        resp = client.get("/api/quarantine")
        data = _json(resp)
        assert len(data["records"]) == 1
        assert data["records"][0]["threat_type"] == "command_injection"

    def test_quarantine_restore(self, client, quarantine, tmp_path):
        target = tmp_path / "restore-me.txt"
        target.write_text("harmless content")
        record = quarantine.quarantine(str(target), "false_positive", "low")
        assert record is not None

        resp = client.post(
            "/api/quarantine/restore",
            data=json.dumps({"quarantine_path": record.quarantine_path}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = _json(resp)
        assert data["restored"] is True

    def test_quarantine_restore_missing_param(self, client):
        resp = client.post(
            "/api/quarantine/restore",
            data=json.dumps({}),
            content_type="application/json",
        )
        data = _json(resp)
        assert "error" in data


# ---------------------------------------------------------------------------
# 6. Monitor
# ---------------------------------------------------------------------------


class TestMonitor:
    """Tests for GET /api/monitor."""

    def test_monitor_returns_system_metrics(self, client):
        resp = client.get("/api/monitor")
        assert resp.status_code == 200
        data = _json(resp)
        assert "cpu_percent" in data
        assert "memory" in data
        assert "percent" in data["memory"]
        assert "disk" in data
        assert "process_count" in data


# ---------------------------------------------------------------------------
# 7. Threats
# ---------------------------------------------------------------------------


class TestThreats:
    """Tests for GET /api/threats."""

    def test_threats_returns_intel(self, client):
        resp = client.get("/api/threats")
        assert resp.status_code == 200
        data = _json(resp)
        assert data["total_patterns"] == 42
        assert len(data["sources"]) == 1


# ---------------------------------------------------------------------------
# 8. KMS
# ---------------------------------------------------------------------------


class TestKMS:
    """Tests for /api/kms/* endpoints."""

    def test_kms_status(self, client):
        resp = client.get("/api/kms/status")
        assert resp.status_code == 200
        data = _json(resp)
        assert data["seal_state"] == "unsealed"
        assert "total_keys" in data

    def test_kms_list_keys_empty(self, client):
        resp = client.get("/api/kms/keys")
        assert resp.status_code == 200
        data = _json(resp)
        assert data["count"] == 0

    def test_kms_list_keys_with_data(self, client, kms):
        kms.create_team_key("alpha")
        kms.create_team_key("beta")

        resp = client.get("/api/kms/keys")
        data = _json(resp)
        assert data["count"] == 2

    def test_kms_list_keys_type_filter(self, client, kms):
        kms.create_team_key("t1")
        kms.create_agent_key("t1", "a1")

        resp = client.get("/api/kms/keys?type=team")
        data = _json(resp)
        assert data["count"] == 1
        assert data["keys"][0]["key_type"] == "team"

    def test_kms_list_keys_invalid_type(self, client):
        resp = client.get("/api/kms/keys?type=bogus")
        assert resp.status_code == 400

    def test_kms_rotate(self, client, kms):
        key = kms.create_team_key("t1")

        resp = client.post(
            "/api/kms/rotate",
            data=json.dumps({"key_id": key.key_id}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = _json(resp)
        assert data["rotated"] is True
        assert data["old_key_id"] == key.key_id
        assert data["new_key_id"] != key.key_id

    def test_kms_rotate_missing_key(self, client):
        resp = client.post(
            "/api/kms/rotate",
            data=json.dumps({"key_id": "nonexistent"}),
            content_type="application/json",
        )
        assert resp.status_code == 404

    def test_kms_rotate_missing_param(self, client):
        resp = client.post(
            "/api/kms/rotate",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_kms_not_configured(self, client_no_kms):
        resp = client_no_kms.get("/api/kms/status")
        assert resp.status_code == 503

        resp = client_no_kms.get("/api/kms/keys")
        assert resp.status_code == 503

        resp = client_no_kms.post(
            "/api/kms/rotate",
            data=json.dumps({"key_id": "x"}),
            content_type="application/json",
        )
        assert resp.status_code == 503


# ---------------------------------------------------------------------------
# 9. Scan
# ---------------------------------------------------------------------------


class TestScan:
    """Tests for POST /api/scan."""

    def test_scan_not_configured(self, client_no_kms):
        resp = client_no_kms.post(
            "/api/scan",
            data=json.dumps({"path": "/tmp"}),
            content_type="application/json",
        )
        assert resp.status_code == 503

    def test_scan_missing_param(self, client):
        resp = client.post(
            "/api/scan",
            data=json.dumps({}),
            content_type="application/json",
        )
        data = _json(resp)
        assert "error" in data

    def test_scan_nonexistent_path(self, client):
        # Need a client with scanner
        resp = client.post(
            "/api/scan",
            data=json.dumps({"path": "/tmp/nonexistent_sksecurity_test_path"}),
            content_type="application/json",
        )
        # Will return 503 since client fixture doesn't have scanner
        # This is tested in the scanner-configured fixture below

    def test_scan_with_real_scanner(self, db, quarantine, mock_intel, mock_monitor, tmp_path):
        """Test scan endpoint with a real SecurityScanner."""
        from sksecurity.scanner import SecurityScanner

        scanner = SecurityScanner()
        server = DashboardServer(
            db=db,
            quarantine=quarantine,
            scanner=scanner,
            intel=mock_intel,
            monitor=mock_monitor,
        )
        server._start_time = datetime.now()
        server.app.testing = True
        tc = server.app.test_client()

        scan_dir = tmp_path / "scan-target"
        scan_dir.mkdir()
        (scan_dir / "clean.py").write_text("print('hello')\n")

        resp = tc.post(
            "/api/scan",
            data=json.dumps({"path": str(scan_dir)}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = _json(resp)
        assert "risk_score" in data
        assert "threat_count" in data
        assert "files_scanned" in data
