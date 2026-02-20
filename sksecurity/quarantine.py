"""SKSecurity Enterprise - Quarantine Management Module"""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import shutil
import json
import os


@dataclass
class QuarantineRecord:
    """Represents a quarantined file."""
    id: Optional[int] = None
    original_path: str = ''
    quarantine_path: str = ''
    threat_type: str = ''
    severity: str = 'medium'
    hash: str = ''
    reason: str = ''
    quarantined_at: datetime = field(default_factory=datetime.now)
    restored: bool = False
    restored_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'original_path': self.original_path,
            'quarantine_path': self.quarantine_path,
            'threat_type': self.threat_type,
            'severity': self.severity,
            'hash': self.hash,
            'reason': self.reason,
            'quarantined_at': self.quarantined_at.isoformat(),
            'restored': self.restored,
            'restored_at': self.restored_at.isoformat() if self.restored_at else None
        }


class QuarantineManager:
    """Manages quarantined files and threats."""
    
    DEFAULT_QUARANTINE_DIR = '~/.sksecurity/quarantine'
    
    def __init__(self, quarantine_dir: Optional[str] = None):
        self.quarantine_dir = Path(quarantine_dir or self.DEFAULT_QUARANTINE_DIR)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self._records: Dict[str, QuarantineRecord] = {}
        self._load_records()
    
    def _load_records(self):
        """Load quarantine records from disk."""
        records_file = self.quarantine_dir / 'records.json'
        if records_file.exists():
            try:
                with open(records_file, 'r') as f:
                    data = json.load(f)
                    for record_data in data:
                        record = QuarantineRecord(
                            id=record_data.get('id'),
                            original_path=record_data.get('original_path', ''),
                            quarantine_path=record_data.get('quarantine_path', ''),
                            threat_type=record_data.get('threat_type', ''),
                            severity=record_data.get('severity', 'medium'),
                            hash=record_data.get('hash', ''),
                            reason=record_data.get('reason', ''),
                            quarantined_at=datetime.fromisoformat(record_data.get('quarantined_at', datetime.now().isoformat())),
                            restored=record_data.get('restored', False),
                            restored_at=datetime.fromisoformat(record_data['restored_at']) if record_data.get('restored_at') else None
                        )
                        self._records[record.quarantine_path] = record
            except Exception:
                pass
    
    def _save_records(self):
        """Save quarantine records to disk."""
        records_file = self.quarantine_dir / 'records.json'
        records_data = [r.to_dict() for r in self._records.values()]
        with open(records_file, 'w') as f:
            json.dump(records_data, f, indent=2)
    
    def _generate_quarantine_path(self, original_path: str) -> str:
        """Generate a unique quarantine path for a file."""
        original = Path(original_path)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_name = original.name.replace('/', '_').replace('\\', '_')
        return str(self.quarantine_dir / f"{timestamp}_{safe_name}")
    
    def quarantine(self, file_path: str, threat_type: str, severity: str = 'medium',
                   reason: str = '') -> Optional[QuarantineRecord]:
        """
        Quarantine a file.
        
        Args:
            file_path: Path to the file to quarantine
            threat_type: Type of threat detected
            severity: Threat severity level
            reason: Description of why the file was quarantined
            
        Returns:
            QuarantineRecord if successful, None if failed
        """
        original = Path(file_path)
        if not original.exists():
            return None
        
        quarantine_path = self._generate_quarantine_path(file_path)
        
        try:
            shutil.move(str(original), quarantine_path)
            
            record = QuarantineRecord(
                original_path=str(original.absolute()),
                quarantine_path=quarantine_path,
                threat_type=threat_type,
                severity=severity,
                hash=self._compute_hash(quarantine_path),
                reason=reason
            )
            
            self._records[quarantine_path] = record
            self._save_records()
            
            return record
            
        except Exception as e:
            print(f"Error quarantining {file_path}: {e}")
            return None
    
    def _compute_hash(self, file_path: str) -> str:
        """Compute SHA256 hash of a file."""
        import hashlib
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def restore(self, quarantine_path: str, restore_original: bool = True) -> bool:
        """
        Restore a quarantined file.
        
        Args:
            quarantine_path: Path to the quarantined file
            restore_original: If True, restore to original location
            
        Returns:
            True if successful, False otherwise
        """
        record = self._records.get(quarantine_path)
        if not record:
            return False
        
        try:
            if restore_original and record.original_path:
                original = Path(record.original_path)
                original.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(quarantine_path, record.original_path)
            else:
                restored_path = str(Path(quarantine_path).parent / f"restored_{Path(quarantine_path).name}")
                shutil.move(quarantine_path, restored_path)
            
            record.restored = True
            record.restored_at = datetime.now()
            self._save_records()
            
            return True
            
        except Exception as e:
            print(f"Error restoring {quarantine_path}: {e}")
            return False
    
    def delete(self, quarantine_path: str) -> bool:
        """
        Permanently delete a quarantined file.
        
        Args:
            quarantine_path: Path to the quarantined file
            
        Returns:
            True if successful, False otherwise
        """
        record = self._records.get(quarantine_path)
        if not record:
            return False
        
        try:
            if Path(quarantine_path).exists():
                os.remove(quarantine_path)
            
            del self._records[quarantine_path]
            self._save_records()
            
            return True
            
        except Exception as e:
            print(f"Error deleting {quarantine_path}: {e}")
            return False
    
    def get_record(self, quarantine_path: str) -> Optional[QuarantineRecord]:
        """Get a quarantine record."""
        return self._records.get(quarantine_path)
    
    def get_all_records(self) -> List[QuarantineRecord]:
        """Get all quarantine records."""
        return list(self._records.values())
    
    def get_active_records(self) -> List[QuarantineRecord]:
        """Get only active (not restored) quarantine records."""
        return [r for r in self._records.values() if not r.restored]
    
    def get_by_threat_type(self, threat_type: str) -> List[QuarantineRecord]:
        """Get quarantine records by threat type."""
        return [r for r in self._records.values() if r.threat_type == threat_type]
    
    def get_by_severity(self, severity: str) -> List[QuarantineRecord]:
        """Get quarantine records by severity."""
        return [r for r in self._records.values() if r.severity == severity]
    
    def clear_all(self, delete_files: bool = False) -> int:
        """
        Clear all quarantine records.
        
        Args:
            delete_files: If True, also delete the quarantined files
            
        Returns:
            Number of records cleared
        """
        count = len(self._records)
        
        if delete_files:
            for path in list(self._records.keys()):
                try:
                    if Path(path).exists():
                        os.remove(path)
                except Exception:
                    pass
        
        self._records.clear()
        self._save_records()
        
        return count
    
    def export_records(self, filepath: str):
        """Export quarantine records to JSON file."""
        data = [r.to_dict() for r in self._records.values()]
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def count(self) -> Dict[str, int]:
        """Get counts by status and severity."""
        active = [r for r in self._records.values() if not r.restored]
        restored = [r for r in self._records.values() if r.restored]
        
        return {
            'total': len(self._records),
            'active': len(active),
            'restored': len(restored),
            'by_severity': {
                'critical': len([r for r in active if r.severity == 'critical']),
                'high': len([r for r in active if r.severity == 'high']),
                'medium': len([r for r in active if r.severity == 'medium']),
                'low': len([r for r in active if r.severity == 'low'])
            }
        }
