"""SKSecurity Enterprise Dashboard — Real-time threat monitoring web interface.

Provides a Flask-based dashboard with live API endpoints backed by
SecurityDatabase, QuarantineManager, RuntimeMonitor, and ThreatIntelligence.
"""

import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import psutil
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

from .database import SecurityDatabase, SecurityEvent
from .intelligence import ThreatIntelligence
from .monitor import RuntimeMonitor
from .quarantine import QuarantineManager


class DashboardServer:
    """Flask dashboard server with real-time security data integration."""

    def __init__(
        self,
        port: int = 8888,
        host: str = "localhost",
        db: Optional[SecurityDatabase] = None,
        quarantine: Optional[QuarantineManager] = None,
        monitor: Optional[RuntimeMonitor] = None,
        intel: Optional[ThreatIntelligence] = None,
    ):
        self.port = port
        self.host = host
        self.app = Flask(__name__)
        CORS(self.app)

        # Wire real data sources (lazy-init if not provided)
        self.db = db or SecurityDatabase()
        self.quarantine = quarantine or QuarantineManager()
        self.monitor = monitor or RuntimeMonitor(check_interval=30)
        self.intel = intel or ThreatIntelligence()

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._setup_routes()

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------

    def _setup_routes(self):
        # ---- Static assets ----
        assets_dir = str(Path(__file__).parent.parent / "assets")

        @self.app.route("/")
        def index():
            return send_from_directory(assets_dir, "dashboard.html")

        @self.app.route("/assets/<path:filename>")
        def serve_asset(filename: str):
            return send_from_directory(assets_dir, filename)

        # ---- Health ----
        @self.app.route("/api/health")
        def health():
            return jsonify(
                {
                    "status": "running",
                    "service": "sksecurity",
                    "uptime_seconds": self._uptime(),
                    "timestamp": datetime.now().isoformat(),
                }
            )

        # ---- Overview (single call for dashboard init) ----
        @self.app.route("/api/overview")
        def overview():
            return jsonify(self._build_overview())

        # ---- Events ----
        @self.app.route("/api/events")
        def events():
            severity = request.args.get("severity")
            limit = int(request.args.get("limit", 50))
            ack = request.args.get("acknowledged")
            acknowledged = None
            if ack is not None:
                acknowledged = ack.lower() in ("true", "1", "yes")
            rows = self.db.get_events(
                severity=severity, limit=limit, acknowledged=acknowledged
            )
            return jsonify(
                {"events": [e.to_dict() for e in rows], "count": len(rows)}
            )

        @self.app.route("/api/events/<int:event_id>/ack", methods=["POST"])
        def ack_event(event_id: int):
            ok = self.db.ack_event(event_id)
            return jsonify({"acknowledged": ok})

        @self.app.route("/api/events/ack-all", methods=["POST"])
        def ack_all():
            severity = request.json.get("severity") if request.is_json else None
            count = self.db.ack_all(severity=severity)
            return jsonify({"acknowledged_count": count})

        # ---- Stats (aggregated counts) ----
        @self.app.route("/api/stats")
        def stats():
            return jsonify(self._build_stats())

        # ---- Quarantine ----
        @self.app.route("/api/quarantine")
        def quarantine_list():
            active = self.quarantine.get_active_records()
            return jsonify(
                {
                    "records": [r.to_dict() for r in active],
                    "counts": self.quarantine.count(),
                }
            )

        # ---- System metrics ----
        @self.app.route("/api/monitor")
        def monitor_metrics():
            mem = psutil.virtual_memory()
            cpu = psutil.cpu_percent(interval=0)
            disk_parts = []
            for p in psutil.disk_partitions():
                try:
                    u = psutil.disk_usage(p.mountpoint)
                    disk_parts.append(
                        {
                            "mount": p.mountpoint,
                            "total_gb": round(u.total / (1024**3), 1),
                            "used_gb": round(u.used / (1024**3), 1),
                            "percent": u.percent,
                        }
                    )
                except PermissionError:
                    pass
            return jsonify(
                {
                    "cpu_percent": cpu,
                    "memory": {
                        "percent": mem.percent,
                        "total_gb": round(mem.total / (1024**3), 1),
                        "used_gb": round(mem.used / (1024**3), 1),
                    },
                    "disk": disk_parts,
                    "process_count": len(psutil.pids()),
                }
            )

        # ---- Threat intelligence ----
        @self.app.route("/api/threats")
        def threats_status():
            return jsonify(self.intel.get_status())

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    _start_time: Optional[datetime] = None

    def _uptime(self) -> float:
        if self._start_time is None:
            return 0.0
        return (datetime.now() - self._start_time).total_seconds()

    def _build_stats(self) -> Dict[str, Any]:
        """Aggregate event counts by severity and type."""
        all_events = self.db.get_events(limit=10000)
        by_severity: Dict[str, int] = {}
        by_type: Dict[str, int] = {}
        unacknowledged = 0
        for ev in all_events:
            by_severity[ev.severity] = by_severity.get(ev.severity, 0) + 1
            by_type[ev.event_type] = by_type.get(ev.event_type, 0) + 1
            if not ev.acknowledged:
                unacknowledged += 1
        qcounts = self.quarantine.count()
        return {
            "total_events": len(all_events),
            "unacknowledged": unacknowledged,
            "by_severity": by_severity,
            "by_type": by_type,
            "quarantine": qcounts,
            "threat_patterns": self.intel.get_status()["total_patterns"],
        }

    def _build_overview(self) -> Dict[str, Any]:
        """Single payload for dashboard bootstrap."""
        recent = self.db.get_events(limit=20)
        stats = self._build_stats()
        mem = psutil.virtual_memory()
        return {
            "health": {
                "status": "running",
                "uptime_seconds": self._uptime(),
            },
            "stats": stats,
            "recent_events": [e.to_dict() for e in recent],
            "system": {
                "cpu_percent": psutil.cpu_percent(interval=0),
                "memory_percent": mem.percent,
                "process_count": len(psutil.pids()),
            },
            "quarantine": self.quarantine.count(),
            "intel": self.intel.get_status(),
            "timestamp": datetime.now().isoformat(),
        }

    # ------------------------------------------------------------------
    # Server lifecycle
    # ------------------------------------------------------------------

    def start(self, blocking: bool = False):
        """Start the dashboard server."""
        self._running = True
        self._start_time = datetime.now()
        # Start the background monitor so we collect metrics
        self.monitor.start()
        if blocking:
            self.app.run(host=self.host, port=self.port)
        else:
            self._thread = threading.Thread(
                target=self.app.run,
                args=(self.host, self.port),
                daemon=True,
            )
            self._thread.start()

    def stop(self):
        """Stop the dashboard server."""
        self._running = False
        self.monitor.stop()

    def get_url(self) -> str:
        return f"http://{self.host}:{self.port}"


class SecurityDashboard:
    """High-level dashboard wrapper with security integration."""

    def __init__(
        self,
        security_scanner=None,
        config=None,
        port: int = 8888,
        db: Optional[SecurityDatabase] = None,
        quarantine: Optional[QuarantineManager] = None,
    ):
        self.server = DashboardServer(port=port, db=db, quarantine=quarantine)
        self.scanner = security_scanner
        self.config = config

    def start(self):
        self.server.start()
        print(f"SKSecurity Dashboard: {self.server.get_url()}")

    def stop(self):
        self.server.stop()

    def add_endpoint(self, route: str, methods: list = ["GET"]):
        """Decorator to add custom endpoints."""

        def decorator(f):
            self.server.app.route(route, methods=methods)(f)
            return f

        return decorator


def launch_dashboard(port: int = 8888, host: str = "localhost"):
    """Launch the SKSecurity dashboard with real data."""
    server = DashboardServer(port=port, host=host)
    print(f"SKSecurity Enterprise Dashboard: http://{host}:{port}")
    server.start(blocking=True)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="SKSecurity Enterprise Dashboard")
    parser.add_argument("--port", type=int, default=8888, help="Port to run on")
    parser.add_argument("--host", type=str, default="localhost", help="Host to bind to")
    args = parser.parse_args()

    print("Launching SKSecurity Enterprise Dashboard...")
    print(f"Dashboard: http://{args.host}:{args.port}")
    launch_dashboard(args.port, args.host)


if __name__ == "__main__":
    main()
