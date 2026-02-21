"""Tests for the QuarantineManager module."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sksecurity.quarantine import QuarantineManager, QuarantineRecord


@pytest.fixture
def qm(tmp_path: Path) -> QuarantineManager:
    """Create a QuarantineManager with temp directory."""
    return QuarantineManager(quarantine_dir=str(tmp_path / "quarantine"))


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    """Create a sample file for quarantine testing."""
    f = tmp_path / "suspicious.py"
    f.write_text("import os; os.system('rm -rf /')\n", encoding="utf-8")
    return f


class TestQuarantineRecord:
    """Tests for the QuarantineRecord dataclass."""

    def test_to_dict(self) -> None:
        """Record converts to dict."""
        record = QuarantineRecord(
            original_path="/tmp/bad.py",
            quarantine_path="/quarantine/bad.py",
            threat_type="malware",
            severity="critical",
        )
        d = record.to_dict()
        assert d["original_path"] == "/tmp/bad.py"
        assert d["severity"] == "critical"

    def test_defaults(self) -> None:
        """Record has sensible defaults."""
        record = QuarantineRecord()
        assert record.restored is False
        assert record.restored_at is None


class TestQuarantineManager:
    """Tests for the QuarantineManager class."""

    def test_creates_quarantine_dir(self, tmp_path: Path) -> None:
        """Quarantine directory is created on init."""
        qdir = tmp_path / "q"
        QuarantineManager(quarantine_dir=str(qdir))
        assert qdir.exists()

    def test_quarantine_file(self, qm: QuarantineManager, sample_file: Path) -> None:
        """File is moved to quarantine."""
        record = qm.quarantine(
            str(sample_file), threat_type="malware", severity="critical",
            reason="Dangerous system call"
        )
        assert record is not None
        assert not sample_file.exists()
        assert Path(record.quarantine_path).exists()
        assert record.threat_type == "malware"
        assert record.hash != ""

    def test_quarantine_nonexistent(self, qm: QuarantineManager) -> None:
        """Quarantining nonexistent file returns None."""
        result = qm.quarantine("/nonexistent/file.py", threat_type="test")
        assert result is None

    def test_restore_file(self, qm: QuarantineManager, sample_file: Path) -> None:
        """Quarantined file can be restored."""
        record = qm.quarantine(str(sample_file), threat_type="test")
        assert record is not None

        success = qm.restore(record.quarantine_path)
        assert success is True
        assert sample_file.exists()

    def test_restore_nonexistent_record(self, qm: QuarantineManager) -> None:
        """Restoring unknown record returns False."""
        assert qm.restore("/nonexistent/record") is False

    def test_delete_quarantined_file(self, qm: QuarantineManager, sample_file: Path) -> None:
        """Quarantined file can be permanently deleted."""
        record = qm.quarantine(str(sample_file), threat_type="test")
        assert record is not None

        success = qm.delete(record.quarantine_path)
        assert success is True
        assert not Path(record.quarantine_path).exists()

    def test_delete_nonexistent_record(self, qm: QuarantineManager) -> None:
        """Deleting unknown record returns False."""
        assert qm.delete("/nonexistent/record") is False

    def test_get_all_records(self, qm: QuarantineManager, tmp_path: Path) -> None:
        """All records can be retrieved."""
        for i in range(3):
            f = tmp_path / f"file_{i}.py"
            f.write_text(f"content {i}", encoding="utf-8")
            qm.quarantine(str(f), threat_type="test")

        records = qm.get_all_records()
        assert len(records) == 3

    def test_get_active_records(self, qm: QuarantineManager, tmp_path: Path) -> None:
        """Active records exclude restored ones."""
        f1 = tmp_path / "f1.py"
        f2 = tmp_path / "f2.py"
        f1.write_text("a", encoding="utf-8")
        f2.write_text("b", encoding="utf-8")

        r1 = qm.quarantine(str(f1), threat_type="test")
        qm.quarantine(str(f2), threat_type="test")

        qm.restore(r1.quarantine_path)

        active = qm.get_active_records()
        assert len(active) == 1

    def test_get_by_threat_type(self, qm: QuarantineManager, tmp_path: Path) -> None:
        """Records can be filtered by threat type."""
        f1 = tmp_path / "a.py"
        f2 = tmp_path / "b.py"
        f1.write_text("x", encoding="utf-8")
        f2.write_text("y", encoding="utf-8")

        qm.quarantine(str(f1), threat_type="malware")
        qm.quarantine(str(f2), threat_type="phishing")

        assert len(qm.get_by_threat_type("malware")) == 1

    def test_get_by_severity(self, qm: QuarantineManager, tmp_path: Path) -> None:
        """Records can be filtered by severity."""
        f1 = tmp_path / "a.py"
        f2 = tmp_path / "b.py"
        f1.write_text("x", encoding="utf-8")
        f2.write_text("y", encoding="utf-8")

        qm.quarantine(str(f1), threat_type="test", severity="critical")
        qm.quarantine(str(f2), threat_type="test", severity="low")

        assert len(qm.get_by_severity("critical")) == 1

    def test_clear_all(self, qm: QuarantineManager, tmp_path: Path) -> None:
        """All records can be cleared."""
        for i in range(3):
            f = tmp_path / f"file_{i}.py"
            f.write_text(f"x{i}", encoding="utf-8")
            qm.quarantine(str(f), threat_type="test")

        count = qm.clear_all(delete_files=True)
        assert count == 3
        assert len(qm.get_all_records()) == 0

    def test_count(self, qm: QuarantineManager, tmp_path: Path) -> None:
        """count() returns breakdown by status and severity."""
        f = tmp_path / "test.py"
        f.write_text("x", encoding="utf-8")
        qm.quarantine(str(f), threat_type="test", severity="critical")

        counts = qm.count()
        assert counts["total"] == 1
        assert counts["active"] == 1
        assert counts["by_severity"]["critical"] == 1

    def test_export_records(self, qm: QuarantineManager, tmp_path: Path) -> None:
        """Records can be exported to JSON."""
        f = tmp_path / "export_test.py"
        f.write_text("data", encoding="utf-8")
        qm.quarantine(str(f), threat_type="export_test")

        export_path = str(tmp_path / "export.json")
        qm.export_records(export_path)

        with open(export_path) as fh:
            data = json.load(fh)
        assert len(data) == 1
        assert data[0]["threat_type"] == "export_test"

    def test_records_persist_across_instances(self, tmp_path: Path) -> None:
        """Records survive QuarantineManager restart."""
        qdir = str(tmp_path / "q")
        f = tmp_path / "persist_test.py"
        f.write_text("persist", encoding="utf-8")

        qm1 = QuarantineManager(quarantine_dir=qdir)
        qm1.quarantine(str(f), threat_type="persist")

        qm2 = QuarantineManager(quarantine_dir=qdir)
        assert len(qm2.get_all_records()) == 1
