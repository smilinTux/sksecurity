"""SKSecurity Enterprise - Security Database Module"""
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime
import json
import sqlite3
import threading
from pathlib import Path


@dataclass
class SecurityEvent:
    """Represents a security event/incident."""
    id: Optional[int] = None
    event_type: str = ''  # 'scan', 'threat', 'quarantine', 'config_change'
    severity: str = 'info'  # 'info', 'low', 'medium', 'high', 'critical'
    source: str = ''  # Which component generated this
    message: str = ''
    details: Dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    acknowledged: bool = False
    
    def to_dict(self) -> Dict:
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        return result


class SecurityDatabase:
    """Manages security events and data persistence."""
    
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or str(Path.home() / '.sksecurity' / 'security.db')
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()
    
    def _init_db(self):
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source TEXT,
                    message TEXT,
                    details TEXT,
                    timestamp TEXT NOT NULL,
                    acknowledged INTEGER DEFAULT 0
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS threat_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator TEXT UNIQUE,
                    severity TEXT,
                    source TEXT,
                    description TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    count INTEGER DEFAULT 1
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS quarantine_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT UNIQUE,
                    original_path TEXT,
                    quarantine_time TEXT,
                    threat_type TEXT,
                    severity TEXT,
                    restored INTEGER DEFAULT 0
                )
            ''')
            conn.commit()
    
    def log_event(self, event: SecurityEvent) -> int:
        """Log a security event to the database."""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    INSERT INTO security_events 
                    (event_type, severity, source, message, details, timestamp, acknowledged)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event.event_type,
                    event.severity,
                    event.source,
                    event.message,
                    json.dumps(event.details),
                    event.timestamp.isoformat(),
                    int(event.acknowledged)
                ))
                conn.commit()
                return cursor.lastrowid
    
    def get_events(self, severity: Optional[str] = None, 
                   limit: int = 100, 
                   acknowledged: Optional[bool] = None) -> List[SecurityEvent]:
        """Get security events with filters."""
        query = 'SELECT * FROM security_events WHERE 1=1'
        params = []
        
        if severity:
            query += ' AND severity = ?'
            params.append(severity)
        if acknowledged is not None:
            query += ' AND acknowledged = ?'
            params.append(int(acknowledged))
        
        query += ' ORDER BY timestamp DESC LIMIT ?'
        params.append(limit)
        
        events = []
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query, params)
            for row in cursor:
                events.append(SecurityEvent(
                    id=row['id'],
                    event_type=row['event_type'],
                    severity=row['severity'],
                    source=row['source'],
                    message=row['message'],
                    details=json.loads(row['details']) if row['details'] else {},
                    timestamp=datetime.fromisoformat(row['timestamp']),
                    acknowledged=bool(row['acknowledged'])
                ))
        return events
    
    def ack_event(self, event_id: int) -> bool:
        """Acknowledge a security event."""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    'UPDATE security_events SET acknowledged = 1 WHERE id = ?',
                    (event_id,)
                )
                conn.commit()
                return cursor.rowcount > 0
    
    def ack_all(self, severity: Optional[str] = None) -> int:
        """Acknowledge all events, optionally filtered by severity."""
        query = 'UPDATE security_events SET acknowledged = 1'
        params = []
        if severity:
            query += ' WHERE severity = ?'
            params.append(severity)
        
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(query, params)
                conn.commit()
                return cursor.rowcount
    
    def export_events(self, filepath: str, start_date: Optional[datetime] = None,
                     end_date: Optional[datetime] = None):
        """Export events to JSON file."""
        query = 'SELECT * FROM security_events WHERE 1=1'
        params = []
        if start_date:
            query += ' AND timestamp >= ?'
            params.append(start_date.isoformat())
        if end_date:
            query += ' AND timestamp <= ?'
            params.append(end_date.isoformat())
        
        events = []
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query, params)
            for row in cursor:
                events.append({
                    'id': row['id'],
                    'type': row['event_type'],
                    'severity': row['severity'],
                    'source': row['source'],
                    'message': row['message'],
                    'timestamp': row['timestamp'],
                    'acknowledged': bool(row['acknowledged'])
                })
        
        with open(filepath, 'w') as f:
            json.dump(events, f, indent=2)
    
    def purge_old(self, days: int = 30) -> int:
        """Delete events older than specified days."""
        cutoff = datetime.now().timestamp() - (days * 24 * 60 * 60)
        cutoff_str = datetime.fromtimestamp(cutoff).isoformat()
        
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    'DELETE FROM security_events WHERE timestamp < ?',
                    (cutoff_str,)
                )
                conn.commit()
                return cursor.rowcount
