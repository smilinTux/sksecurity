"""Tests for the RuntimeMonitor and SecurityMonitor modules."""

from __future__ import annotations

import time
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from sksecurity.monitor import MonitorEvent, RuntimeMonitor, SecurityMonitor


class TestMonitorEvent:
    """Tests for the MonitorEvent dataclass."""

    def test_to_dict(self) -> None:
        """Event converts to dict."""
        event = MonitorEvent(type="process", severity="high", message="CPU spike")
        d = event.to_dict()
        assert d["type"] == "process"
        assert d["severity"] == "high"
        assert "timestamp" in d

    def test_defaults(self) -> None:
        """Event has sensible defaults."""
        event = MonitorEvent(type="test")
        assert event.severity == "info"
        assert event.message == ""


class TestRuntimeMonitor:
    """Tests for the RuntimeMonitor class."""

    def test_init(self) -> None:
        """Monitor initializes with correct state."""
        monitor = RuntimeMonitor(check_interval=30)
        assert monitor.check_interval == 30
        assert monitor._running is False

    def test_start_stop(self) -> None:
        """Monitor starts and stops cleanly."""
        monitor = RuntimeMonitor(check_interval=9999)
        monitor.start()
        assert monitor._running is True
        monitor.stop()
        assert monitor._running is False

    def test_double_start_is_safe(self) -> None:
        """Starting twice doesn't create extra threads."""
        monitor = RuntimeMonitor(check_interval=9999)
        monitor.start()
        thread1 = monitor._thread
        monitor.start()
        thread2 = monitor._thread
        assert thread1 is thread2
        monitor.stop()

    def test_on_event_callback(self) -> None:
        """Registered callbacks receive events."""
        monitor = RuntimeMonitor()
        received = []
        monitor.on_event(lambda e: received.append(e))
        monitor._emit(MonitorEvent(type="test", message="hello"))
        assert len(received) == 1
        assert received[0].message == "hello"

    def test_callback_exception_handled(self) -> None:
        """Exceptions in callbacks don't crash the emitter."""
        monitor = RuntimeMonitor()
        monitor.on_event(lambda e: 1 / 0)
        received = []
        monitor.on_event(lambda e: received.append(e))

        monitor._emit(MonitorEvent(type="test"))
        assert len(received) == 1

    def test_get_accessors(self) -> None:
        """Accessor methods return correct types."""
        monitor = RuntimeMonitor()
        assert isinstance(monitor.get_cpu_percent(), float)
        assert isinstance(monitor.get_memory_percent(), float)
        assert isinstance(monitor.get_process_count(), int)

    def test_list_processes(self) -> None:
        """list_processes returns list of dicts."""
        monitor = RuntimeMonitor()
        procs = monitor.list_processes()
        assert isinstance(procs, list)


class TestSecurityMonitor:
    """Tests for the SecurityMonitor class."""

    def _make_config(self) -> MagicMock:
        """Create a mock config object."""
        config = MagicMock()
        config.get.return_value = 9999
        config.runtime_monitoring = False
        return config

    def test_init(self) -> None:
        """SecurityMonitor initializes with config."""
        config = self._make_config()
        sm = SecurityMonitor(config)
        assert sm.runtime_monitor is not None

    def test_event_collection(self) -> None:
        """Events are collected from the runtime monitor."""
        config = self._make_config()
        sm = SecurityMonitor(config)

        event = MonitorEvent(type="test", message="collected")
        sm._on_event(event)
        events = sm.get_events()
        assert len(events) == 1

    def test_get_events_since(self) -> None:
        """Events can be filtered by timestamp."""
        config = self._make_config()
        sm = SecurityMonitor(config)

        old = MonitorEvent(type="test", message="old")
        old.timestamp = datetime.now() - timedelta(hours=2)
        sm._on_event(old)

        new = MonitorEvent(type="test", message="new")
        sm._on_event(new)

        since = datetime.now() - timedelta(hours=1)
        recent = sm.get_events(since=since)
        assert len(recent) == 1
        assert recent[0].message == "new"

    def test_get_recent_events(self) -> None:
        """get_recent_events returns limited sorted results."""
        config = self._make_config()
        sm = SecurityMonitor(config)

        for i in range(5):
            sm._on_event(MonitorEvent(type="test", message=f"e{i}"))

        recent = sm.get_recent_events(count=2)
        assert len(recent) == 2

    def test_get_stats(self) -> None:
        """Stats include event totals."""
        config = self._make_config()
        sm = SecurityMonitor(config)
        sm._on_event(MonitorEvent(type="test"))
        stats = sm.get_stats()
        assert stats["total_events"] == 1

    def test_start_with_monitoring_disabled(self) -> None:
        """Starting with monitoring disabled doesn't crash."""
        config = self._make_config()
        config.runtime_monitoring = False
        sm = SecurityMonitor(config)
        sm.start()
        sm.stop()
