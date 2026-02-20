"""SKSecurity Enterprise - Runtime Monitoring Module"""
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
import threading
import time
import os
import psutil


@dataclass
class MonitorEvent:
    """Represents a monitoring event."""
    type: str  # 'process', 'memory', 'disk', 'network', 'file_change'
    severity: str = 'info'
    message: str = ''
    details: Dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        return {
            'type': self.type,
            'severity': self.severity,
            'message': self.message,
            'details': self.details,
            'timestamp': self.timestamp.isoformat()
        }


class RuntimeMonitor:
    """Monitors system resources and processes."""
    
    def __init__(self, check_interval: int = 60):
        self.check_interval = check_interval
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callbacks: List[Callable[[MonitorEvent], None]] = []
        self._last_cpu = 0.0
        self._last_memory = 0.0
        self._processes: Dict[int, Dict] = {}
    
    def start(self):
        """Start the monitoring thread."""
        if self._running:
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
    
    def stop(self):
        """Stop the monitoring thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
    
    def on_event(self, callback: Callable[[MonitorEvent], None]):
        """Register a callback for monitoring events."""
        self._callbacks.append(callback)
    
    def _emit(self, event: MonitorEvent):
        """Emit a monitoring event to all callbacks."""
        for callback in self._callbacks:
            try:
                callback(event)
            except Exception:
                pass
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self._running:
            try:
                self._check_cpu()
                self._check_memory()
                self._check_disk()
                self._check_processes()
            except Exception:
                pass
            time.sleep(self.check_interval)
    
    def _check_cpu(self):
        """Check CPU usage."""
        cpu_percent = psutil.cpu_percent(interval=1)
        if cpu_percent > 90:
            self._emit(MonitorEvent(
                type='process',
                severity='high',
                message=f'High CPU usage: {cpu_percent}%',
                details={'cpu_percent': cpu_percent}
            ))
        self._last_cpu = cpu_percent
    
    def _check_memory(self):
        """Check memory usage."""
        memory = psutil.virtual_memory()
        if memory.percent > 90:
            self._emit(MonitorEvent(
                type='memory',
                severity='high',
                message=f'High memory usage: {memory.percent}%',
                details={'percent': memory.percent, 'used_gb': memory.used / (1024**3)}
            ))
        self._last_memory = memory.percent
    
    def _check_disk(self):
        """Check disk usage."""
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                if usage.percent > 90:
                    self._emit(MonitorEvent(
                        type='disk',
                        severity='high',
                        message=f'High disk usage on {partition.mountpoint}: {usage.percent}%',
                        details={'mountpoint': partition.mountpoint, 'percent': usage.percent}
                    ))
            except PermissionError:
                pass
    
    def _check_processes(self):
        """Check for suspicious processes."""
        current_pids = set()
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                info = proc.info
                pid = info['pid']
                current_pids.add(pid)
                
                if pid not in self._processes:
                    self._processes[pid] = {
                        'name': info['name'],
                        'first_seen': datetime.now(),
                        'cmdline': info.get('cmdline', [])
                    }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        for pid in list(self._processes.keys()):
            if pid not in current_pids:
                del self._processes[pid]
    
    def get_cpu_percent(self) -> float:
        """Get current CPU usage."""
        return self._last_cpu
    
    def get_memory_percent(self) -> float:
        """Get current memory usage."""
        return self._last_memory
    
    def get_process_count(self) -> int:
        """Get number of tracked processes."""
        return len(self._processes)
    
    def list_processes(self) -> List[Dict]:
        """List tracked processes."""
        return [
            {
                'pid': pid,
                'name': info['name'],
                'first_seen': info['first_seen'].isoformat(),
                'cmdline': info['cmdline']
            }
            for pid, info in self._processes.items()
        ]


class SecurityMonitor:
    """Higher-level security monitoring wrapper."""
    
    def __init__(self, config):
        self.config = config
        self.runtime_monitor = RuntimeMonitor(
            check_interval=config.get('monitoring.check_interval', 60)
        )
        self._events: List[MonitorEvent] = []
        self._lock = threading.Lock()
        
        self.runtime_monitor.on_event(self._on_event)
    
    def _on_event(self, event: MonitorEvent):
        """Handle monitoring events."""
        with self._lock:
            self._events.append(event)
    
    def start(self):
        """Start all monitoring."""
        if self.config.runtime_monitoring:
            self.runtime_monitor.start()
    
    def stop(self):
        """Stop all monitoring."""
        self.runtime_monitor.stop()
    
    def get_events(self, since: Optional[datetime] = None) -> List[MonitorEvent]:
        """Get monitoring events."""
        with self._lock:
            if since:
                return [e for e in self._events if e.timestamp > since]
            return list(self._events)
    
    def get_recent_events(self, count: int = 10) -> List[MonitorEvent]:
        """Get most recent events."""
        with self._lock:
            return sorted(self._events, key=lambda e: e.timestamp, reverse=True)[:count]
    
    def get_stats(self) -> Dict:
        """Get monitoring statistics."""
        with self._lock:
            return {
                'total_events': len(self._events),
                'by_type': {},
                'by_severity': {}
            }
