#!/usr/bin/env python3
"""
Security Dashboard Web Interface
Real-time security monitoring and threat visualization
"""

import json
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class SecurityDashboardHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.security_dir = Path("/home/cbrd21/clawd/skills/security-scanner")
        self.db_path = self.security_dir / "security.db"
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        if self.path == '/':
            self.serve_dashboard()
        elif self.path == '/api/status':
            self.serve_api_status()
        elif self.path == '/api/threats':
            self.serve_api_threats()
        elif self.path == '/api/skills':
            self.serve_api_skills()
        else:
            self.send_error(404)
    
    def serve_dashboard(self):
        """Serve main dashboard HTML"""
        html = self.generate_dashboard_html()
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def serve_api_status(self):
        """Serve security status API"""
        status = self.get_security_status()
        self.send_json_response(status)
    
    def serve_api_threats(self):
        """Serve threats API"""
        threats = self.get_recent_threats()
        self.send_json_response(threats)
    
    def serve_api_skills(self):
        """Serve skills security API"""
        skills = self.get_skills_security()
        self.send_json_response(skills)
    
    def send_json_response(self, data):
        """Send JSON response"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())
    
    def get_security_status(self):
        """Get overall security status"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Threat intelligence status
                cursor = conn.execute("SELECT COUNT(*) FROM threat_intelligence")
                threat_count = cursor.fetchone()[0]
                
                # Recent events
                since = datetime.now() - timedelta(hours=24)
                cursor = conn.execute("""
                    SELECT severity, COUNT(*) 
                    FROM security_events 
                    WHERE timestamp > ? 
                    GROUP BY severity
                """, (since.isoformat(),))
                
                events_24h = dict(cursor.fetchall())
                
                return {
                    'timestamp': datetime.now().isoformat(),
                    'threat_patterns': threat_count,
                    'events_24h': events_24h,
                    'status': 'SECURE' if events_24h.get('CRITICAL', 0) == 0 else 'ALERT'
                }
        except Exception as e:
            return {'error': str(e)}
    
    def get_recent_threats(self):
        """Get recent security threats"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT timestamp, event_type, severity, description, metadata
                    FROM security_events 
                    WHERE severity IN ('CRITICAL', 'HIGH')
                    ORDER BY timestamp DESC 
                    LIMIT 20
                """)
                
                return [
                    {
                        'timestamp': row[0],
                        'type': row[1],
                        'severity': row[2],
                        'description': row[3],
                        'metadata': json.loads(row[4] or '{}')
                    }
                    for row in cursor.fetchall()
                ]
        except Exception as e:
            return [{'error': str(e)}]
    
    def get_skills_security(self):
        """Get skills security overview"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT skill_name, trust_score, risk_level, last_scan, threat_count
                    FROM skill_reputation 
                    ORDER BY trust_score ASC
                    LIMIT 50
                """)
                
                return [
                    {
                        'skill': row[0],
                        'trust_score': row[1],
                        'risk_level': row[2],
                        'last_scan': row[3],
                        'threat_count': row[4]
                    }
                    for row in cursor.fetchall()
                ]
        except Exception as e:
            return [{'error': str(e)}]
    
    def generate_dashboard_html(self):
        """Generate dashboard HTML"""
        return '''<!DOCTYPE html>
<html>
<head>
    <title>🛡️ SKStacks Security Operations Center</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1e3c72, #2a5298);
            color: white;
            min-height: 100vh;
        }
        .header {
            background: rgba(0,0,0,0.2);
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        .header h1 { font-size: 1.5rem; }
        .status-indicator {
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .status-secure { background: #4CAF50; }
        .status-alert { background: #f44336; }
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
            padding: 2rem;
            max-width: 1400px;
            margin: 0 auto;
        }
        .card {
            background: rgba(255,255,255,0.1);
            border-radius: 10px;
            padding: 1.5rem;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.2);
        }
        .card h2 {
            margin-bottom: 1rem;
            color: #64B5F6;
            font-size: 1.2rem;
        }
        .metric {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.5rem 0;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        .metric:last-child { border-bottom: none; }
        .metric-value {
            font-weight: bold;
            font-size: 1.1rem;
        }
        .threat-item {
            background: rgba(255,255,255,0.05);
            padding: 1rem;
            margin: 0.5rem 0;
            border-radius: 5px;
            border-left: 3px solid;
        }
        .threat-critical { border-color: #f44336; }
        .threat-high { border-color: #ff9800; }
        .skill-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.5rem;
            margin: 0.25rem 0;
            background: rgba(255,255,255,0.05);
            border-radius: 5px;
        }
        .trust-score {
            padding: 0.25rem 0.5rem;
            border-radius: 12px;
            font-size: 0.8rem;
            font-weight: bold;
        }
        .trust-high { background: #4CAF50; }
        .trust-medium { background: #ff9800; }
        .trust-low { background: #f44336; }
        .loading { text-align: center; opacity: 0.7; }
        .timestamp {
            font-size: 0.8rem;
            opacity: 0.7;
            margin-top: 0.5rem;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ SKStacks Security Operations Center</h1>
        <div id="status-indicator" class="status-indicator status-secure">SECURE</div>
    </div>
    
    <div class="dashboard">
        <div class="card">
            <h2>📊 Security Status</h2>
            <div id="security-status">
                <div class="loading">Loading security status...</div>
            </div>
        </div>
        
        <div class="card">
            <h2>🚨 Recent Threats</h2>
            <div id="recent-threats">
                <div class="loading">Loading threats...</div>
            </div>
        </div>
        
        <div class="card">
            <h2>🔍 Skills Security</h2>
            <div id="skills-security">
                <div class="loading">Loading skills data...</div>
            </div>
        </div>
        
        <div class="card">
            <h2>📈 Security Metrics</h2>
            <div class="metric">
                <span>Threat Patterns</span>
                <span class="metric-value" id="threat-count">-</span>
            </div>
            <div class="metric">
                <span>Skills Monitored</span>
                <span class="metric-value" id="skills-count">-</span>
            </div>
            <div class="metric">
                <span>Average Trust Score</span>
                <span class="metric-value" id="avg-trust">-</span>
            </div>
            <div class="metric">
                <span>Last Update</span>
                <span class="metric-value" id="last-update">-</span>
            </div>
        </div>
    </div>

    <script>
        function updateDashboard() {
            // Update security status
            fetch('/api/status')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('status-indicator').textContent = data.status;
                    document.getElementById('status-indicator').className = 
                        'status-indicator ' + (data.status === 'SECURE' ? 'status-secure' : 'status-alert');
                    
                    document.getElementById('threat-count').textContent = data.threat_patterns || '0';
                    document.getElementById('last-update').textContent = 
                        new Date(data.timestamp).toLocaleTimeString();
                    
                    const statusHtml = Object.entries(data.events_24h || {})
                        .map(([severity, count]) => 
                            `<div class="metric">
                                <span>${severity} Events (24h)</span>
                                <span class="metric-value">${count}</span>
                            </div>`
                        ).join('');
                    
                    document.getElementById('security-status').innerHTML = 
                        statusHtml || '<div class="metric"><span>No events</span><span class="metric-value">✅</span></div>';
                });
            
            // Update recent threats
            fetch('/api/threats')
                .then(r => r.json())
                .then(data => {
                    const threatsHtml = data.slice(0, 10).map(threat => 
                        `<div class="threat-item threat-${threat.severity.toLowerCase()}">
                            <strong>${threat.severity}: ${threat.type}</strong>
                            <div>${threat.description}</div>
                            <div class="timestamp">${new Date(threat.timestamp).toLocaleString()}</div>
                        </div>`
                    ).join('');
                    
                    document.getElementById('recent-threats').innerHTML = 
                        threatsHtml || '<div style="text-align:center;opacity:0.7;">No recent threats ✅</div>';
                });
            
            // Update skills security
            fetch('/api/skills')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('skills-count').textContent = data.length;
                    
                    const avgTrust = data.length ? 
                        (data.reduce((sum, s) => sum + (s.trust_score || 0), 0) / data.length).toFixed(1) : 
                        '0.0';
                    document.getElementById('avg-trust').textContent = avgTrust;
                    
                    const skillsHtml = data.slice(0, 15).map(skill => {
                        const trustClass = skill.trust_score >= 70 ? 'trust-high' : 
                                          skill.trust_score >= 40 ? 'trust-medium' : 'trust-low';
                        
                        return `<div class="skill-item">
                            <span>${skill.skill}</span>
                            <span class="trust-score ${trustClass}">${skill.trust_score || 0}%</span>
                        </div>`;
                    }).join('');
                    
                    document.getElementById('skills-security').innerHTML = 
                        skillsHtml || '<div style="text-align:center;opacity:0.7;">No skills data</div>';
                });
        }
        
        // Update dashboard every 30 seconds
        updateDashboard();
        setInterval(updateDashboard, 30000);
    </script>
</body>
</html>'''

def main():
    print("🛡️ Starting Security Dashboard Server")
    print("📍 http://localhost:8888")
    print("Press Ctrl+C to stop")
    
    server = HTTPServer(('localhost', 8888), SecurityDashboardHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Dashboard server stopped")
        server.server_close()

if __name__ == '__main__':
    main()