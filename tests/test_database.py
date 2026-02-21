"""Tests for the SecurityDatabase module."""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from sksecurity.database import SecurityDatabase, SecurityEvent


@pytest.fixture
def db(tmp_path: Path) -> SecurityDatabase:
    """Create a test database."""
    return SecurityDatabase(db_path=str(tmp_path / "test.db"))


def _make_event(**kwargs) -> SecurityEvent:
    """Helper to create test events."""
    defaults = {
        "event_type": "test",
        "severity": "info",
        "source": "test_suite",
        "message": "Test event",
        "details": {"key": "value"},
    }
    defaults.update(kwargs)
    return SecurityEvent(**defaults)


class TestSecurityEvent:
    """Tests for the SecurityEvent dataclass."""

    def test_to_dict(self) -> None:
        """Event converts to dict with ISO timestamp."""
        event = _make_event()
        d = event.to_dict()
        assert d["event_type"] == "test"
        assert isinstance(d["timestamp"], str)

    def test_defaults(self) -> None:
        """Event has sensible defaults."""
        event = SecurityEvent()
        assert event.acknowledged is False
        assert event.severity == "info"


class TestSecurityDatabase:
    """Tests for the SecurityDatabase class."""

    def test_creates_db_file(self, tmp_path: Path) -> None:
        """Database file is created on init."""
        db_path = tmp_path / "sub" / "security.db"
        SecurityDatabase(db_path=str(db_path))
        assert db_path.exists()

    def test_log_event(self, db: SecurityDatabase) -> None:
        """Events can be logged and return an ID."""
        event = _make_event()
        event_id = db.log_event(event)
        assert isinstance(event_id, int)
        assert event_id > 0

    def test_get_events(self, db: SecurityDatabase) -> None:
        """Logged events can be retrieved."""
        db.log_event(_make_event(message="first"))
        db.log_event(_make_event(message="second"))
        events = db.get_events()
        assert len(events) == 2

    def test_get_events_by_severity(self, db: SecurityDatabase) -> None:
        """Events can be filtered by severity."""
        db.log_event(_make_event(severity="info"))
        db.log_event(_make_event(severity="critical"))
        db.log_event(_make_event(severity="info"))

        info_events = db.get_events(severity="info")
        assert len(info_events) == 2

        critical_events = db.get_events(severity="critical")
        assert len(critical_events) == 1

    def test_get_events_limit(self, db: SecurityDatabase) -> None:
        """Event retrieval respects limit."""
        for i in range(10):
            db.log_event(_make_event(message=f"event-{i}"))
        events = db.get_events(limit=3)
        assert len(events) == 3

    def test_ack_event(self, db: SecurityDatabase) -> None:
        """Individual events can be acknowledged."""
        event_id = db.log_event(_make_event())
        assert db.ack_event(event_id) is True

        events = db.get_events(acknowledged=True)
        assert len(events) == 1

    def test_ack_nonexistent(self, db: SecurityDatabase) -> None:
        """Acknowledging nonexistent event returns False."""
        assert db.ack_event(99999) is False

    def test_ack_all(self, db: SecurityDatabase) -> None:
        """All events can be acknowledged at once."""
        db.log_event(_make_event(severity="info"))
        db.log_event(_make_event(severity="high"))
        count = db.ack_all()
        assert count == 2

    def test_ack_all_by_severity(self, db: SecurityDatabase) -> None:
        """ack_all can filter by severity."""
        db.log_event(_make_event(severity="info"))
        db.log_event(_make_event(severity="critical"))
        count = db.ack_all(severity="info")
        assert count == 1

    def test_export_events(self, db: SecurityDatabase, tmp_path: Path) -> None:
        """Events can be exported to JSON."""
        db.log_event(_make_event(message="exported"))
        export_path = str(tmp_path / "export.json")
        db.export_events(export_path)

        with open(export_path) as f:
            data = json.load(f)
        assert len(data) == 1
        assert data[0]["message"] == "exported"

    def test_purge_old(self, db: SecurityDatabase) -> None:
        """Old events can be purged."""
        old_event = _make_event(message="old")
        old_event.timestamp = datetime.now() - timedelta(days=60)
        db.log_event(old_event)

        new_event = _make_event(message="new")
        db.log_event(new_event)

        purged = db.purge_old(days=30)
        assert purged == 1

        remaining = db.get_events()
        assert len(remaining) == 1

    def test_filter_acknowledged(self, db: SecurityDatabase) -> None:
        """Events can be filtered by acknowledged status."""
        eid = db.log_event(_make_event())
        db.log_event(_make_event())
        db.ack_event(eid)

        acked = db.get_events(acknowledged=True)
        unacked = db.get_events(acknowledged=False)
        assert len(acked) == 1
        assert len(unacked) == 1

    def test_thread_safety(self, db: SecurityDatabase) -> None:
        """Database operations are thread-safe."""
        import threading

        def log_many():
            for _ in range(20):
                db.log_event(_make_event())

        threads = [threading.Thread(target=log_many) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        events = db.get_events(limit=200)
        assert len(events) == 80
