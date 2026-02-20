#!/usr/bin/env python3
"""
SKSecurity Enterprise Dashboard Module
Provides web dashboard and API for security monitoring
"""

import os
import sys
import subprocess
import threading
from pathlib import Path
from typing import Optional, Dict, Any
from flask import Flask, jsonify, render_template_string
from flask_cors import CORS


class DashboardServer:
    """Embedded Flask dashboard server for SKSecurity."""
    
    def __init__(self, port: int = 8888, host: str = 'localhost'):
        self.port = port
        self.host = host
        self.app = Flask(__name__)
        CORS(self.app)
        self._setup_routes()
        self._running = False
        self._thread: Optional[threading.Thread] = None
    
    def _setup_routes(self):
        """Setup Flask routes for the dashboard."""
        
        @self.app.route('/')
        def index():
            return '''
            <!DOCTYPE html>
            <html>
            <head><title>SKSecurity Dashboard</title></head>
            <body>
                <h1>🛡️ SKSecurity Enterprise</h1>
                <p>Security Dashboard Running</p>
                <p>API Endpoints:</p>
                <ul>
                    <li>/api/health - Health check</li>
                    <li>/api/stats - Security statistics</li>
                    <li>/api/events - Recent events</li>
                </ul>
            </body>
            </html>
            '''
        
        @self.app.route('/api/health')
        def health():
            return jsonify({'status': 'running', 'service': 'sksecurity'})
        
        @self.app.route('/api/stats')
        def stats():
            return jsonify({
                'status': 'healthy',
                'version': '1.0.0',
                'components': {
                    'scanner': 'active',
                    'monitor': 'active',
                    'database': 'active'
                }
            })
        
        @self.app.route('/api/events')
        def events():
            return jsonify({'events': [], 'count': 0})
    
    def start(self, blocking: bool = False):
        """Start the dashboard server."""
        self._running = True
        if blocking:
            self.app.run(host=self.host, port=self.port)
        else:
            self._thread = threading.Thread(
                target=self.app.run,
                args=(self.host, self.port),
                daemon=True
            )
            self._thread.start()
    
    def stop(self):
        """Stop the dashboard server."""
        self._running = False
        # Note: Flask doesn't have a clean stop, thread will die on process exit
    
    def get_url(self) -> str:
        """Get the dashboard URL."""
        return f"http://{self.host}:{self.port}"


class SecurityDashboard:
    """High-level dashboard wrapper with security integration."""
    
    def __init__(self, security_scanner=None, config=None, port: int = 8888):
        self.server = DashboardServer(port=port)
        self.scanner = security_scanner
        self.config = config
    
    def start(self):
        """Start the dashboard."""
        self.server.start()
        print(f"🛡️ SKSecurity Dashboard: {self.server.get_url()}")
    
    def stop(self):
        """Stop the dashboard."""
        self.server.stop()
    
    def add_endpoint(self, route: str, methods: list = ['GET']):
        """Decorator to add custom endpoints."""
        def decorator(f):
            self.server.app.route(route, methods=methods)(f)
            return f
        return decorator


def launch_dashboard(port=8888, host='localhost'):
    """Launch the SKSecurity security dashboard"""
    # Find the dashboard script
    script_path = Path(__file__).parent.parent / "scripts" / "security_dashboard.py"
    
    if script_path.exists():
        # Run the dashboard script
        subprocess.run([sys.executable, str(script_path), "--port", str(port), "--host", host])
    else:
        print("🚨 Dashboard script not found. Please check your installation.")
        print("Expected location:", script_path)
        return False
    
    return True

def main():
    """Main entry point for dashboard command"""
    import argparse
    
    parser = argparse.ArgumentParser(description='SKSecurity Enterprise Dashboard')
    parser.add_argument('--port', type=int, default=8888, help='Port to run dashboard on')
    parser.add_argument('--host', type=str, default='localhost', help='Host to bind to')
    
    args = parser.parse_args()
    
    print("🛡️ Launching SKSecurity Enterprise Dashboard...")
    print(f"📊 Dashboard will be available at: http://{args.host}:{args.port}")
    
    launch_dashboard(args.port, args.host)

if __name__ == "__main__":
    main()