#!/usr/bin/env python3
"""
Advanced AI Agent Security System
Implements multi-layered defense with AI-powered threat intelligence
"""

import os
import sys
import json
import subprocess
import hashlib
import time
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timedelta
import threading
import signal
import sqlite3
from collections import defaultdict
import re

class AdvancedSecuritySystem:
    def __init__(self):
        self.workspace = Path("/home/cbrd21/clawd")
        self.security_dir = self.workspace / "skills" / "security-scanner"
        self.db_path = self.security_dir / "security.db"
        self.quarantine_dir = self.workspace / "quarantine"
        self.logs_dir = self.security_dir / "logs"
        
        # Security configuration
        self.threat_sources = [
            {"name": "Moltbook", "url": "https://www.moltbook.com/security-feed.json", "priority": 1},
            {"name": "NVD", "url": "https://services.nvd.nist.gov/rest/json/cves/2.0", "priority": 2},
            {"name": "GitHub", "url": "https://api.github.com/advisories", "priority": 3},
        ]
        
        self.init_system()
    
    def init_system(self):
        """Initialize security system components"""
        self.quarantine_dir.mkdir(exist_ok=True)
        self.logs_dir.mkdir(exist_ok=True)
        self.init_database()
        self.log("Advanced Security System initialized", "SYSTEM")
    
    def init_database(self):
        """Initialize security database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT,
                    event_type TEXT,
                    severity TEXT,
                    source TEXT,
                    description TEXT,
                    metadata TEXT
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS skill_reputation (
                    skill_name TEXT PRIMARY KEY,
                    trust_score REAL,
                    risk_level TEXT,
                    last_scan TEXT,
                    threat_count INTEGER,
                    usage_count INTEGER
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS threat_intelligence (
                    id INTEGER PRIMARY KEY,
                    source TEXT,
                    threat_type TEXT,
                    pattern TEXT,
                    severity TEXT,
                    confidence REAL,
                    first_seen TEXT,
                    last_updated TEXT
                )
            ''')
    
    def log(self, message, level="INFO", metadata=None):
        """Enhanced logging with database storage"""
        timestamp = datetime.now().isoformat()
        log_entry = f"[{timestamp}] {level}: {message}"
        print(log_entry)
        
        # Store in database
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO security_events 
                (timestamp, event_type, severity, source, description, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (timestamp, level, level, "security_system", message, json.dumps(metadata or {})))
        
        # Write to log file
        log_file = self.logs_dir / f"security_{datetime.now().strftime('%Y%m%d')}.log"
        with open(log_file, 'a') as f:
            f.write(log_entry + "\n")
    
    def enhanced_threat_intelligence(self):
        """Advanced multi-source threat intelligence gathering"""
        self.log("🧠 Advanced Threat Intelligence Collection", "SECURITY")
        
        all_threats = []
        
        # Collect from multiple sources
        for source in self.threat_sources:
            try:
                self.log(f"Fetching from {source['name']}")
                threats = self.fetch_threat_source(source)
                if threats:
                    all_threats.extend(threats)
                    self.log(f"✅ {source['name']}: {len(threats)} threats")
                    
            except Exception as e:
                self.log(f"❌ {source['name']}: {e}", "ERROR")
        
        # Add AI-enhanced patterns
        ai_threats = self.generate_ai_threat_patterns()
        all_threats.extend(ai_threats)
        
        # Store in database
        self.store_threat_intelligence(all_threats)
        
        self.log(f"🎯 Total threat patterns collected: {len(all_threats)}", "SECURITY")
        return all_threats
    
    def fetch_threat_source(self, source):
        """Fetch threats from individual source"""
        if source["name"] == "Moltbook":
            return self.fetch_moltbook_threats(source["url"])
        elif source["name"] == "NVD":
            return self.fetch_nvd_threats(source["url"])
        elif source["name"] == "GitHub":
            return self.fetch_github_threats(source["url"])
        return []
    
    def fetch_moltbook_threats(self, url):
        """Fetch from Moltbook security feed"""
        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                if response.getcode() == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    return data.get('threats', [])
        except:
            pass
        return []
    
    def fetch_nvd_threats(self, url):
        """Fetch from National Vulnerability Database"""
        # Placeholder - would integrate with NVD API
        return [
            {"type": "buffer_overflow", "pattern": r"strcpy|strcat|sprintf", "severity": "HIGH"},
            {"type": "injection", "pattern": r"system\(|exec\(", "severity": "CRITICAL"},
        ]
    
    def fetch_github_threats(self, url):
        """Fetch from GitHub Security Advisories"""
        # Placeholder - would integrate with GitHub API
        return [
            {"type": "dependency_vulnerability", "pattern": r"require\(['\"].*['\"]", "severity": "MEDIUM"},
            {"type": "secrets_exposure", "pattern": r"(github_pat_|ghp_)", "severity": "HIGH"},
        ]
    
    def generate_ai_threat_patterns(self):
        """AI-enhanced threat pattern generation"""
        return [
            {"type": "obfuscated_code", "pattern": r"eval\(.*(?:atob|unescape|fromCharCode)", "severity": "CRITICAL"},
            {"type": "reverse_shell", "pattern": r"socket\.socket.*connect.*exec", "severity": "CRITICAL"},
            {"type": "privilege_escalation", "pattern": r"sudo.*NOPASSWD|setuid\(0\)", "severity": "HIGH"},
            {"type": "crypto_mining", "pattern": r"(xmrig|cryptonight|monero)", "severity": "HIGH"},
            {"type": "keylogger", "pattern": r"(keyboard|keypress).*log", "severity": "HIGH"},
            {"type": "ransomware", "pattern": r"encrypt.*\.(txt|doc|pdf)", "severity": "CRITICAL"},
        ]
    
    def store_threat_intelligence(self, threats):
        """Store threat intelligence in database"""
        with sqlite3.connect(self.db_path) as conn:
            # Clear old threats
            conn.execute("DELETE FROM threat_intelligence")
            
            # Insert new threats
            for threat in threats:
                conn.execute('''
                    INSERT INTO threat_intelligence 
                    (source, threat_type, pattern, severity, confidence, first_seen, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    threat.get('source', 'unknown'),
                    threat.get('type', 'unknown'),
                    threat.get('pattern', ''),
                    threat.get('severity', 'MEDIUM'),
                    threat.get('confidence', 0.8),
                    datetime.now().isoformat(),
                    datetime.now().isoformat()
                ))
    
    def advanced_skill_scan(self, skill_path):
        """Enhanced skill scanning with AI analysis"""
        self.log(f"🔍 Advanced scan: {skill_path.name}", "SECURITY")
        
        threats = []
        skill_path = Path(skill_path)
        
        # Multi-layer scanning
        threats.extend(self.static_analysis_scan(skill_path))
        threats.extend(self.behavioral_analysis_scan(skill_path))
        threats.extend(self.dependency_analysis_scan(skill_path))
        threats.extend(self.ai_powered_analysis(skill_path))
        
        # Calculate risk score
        risk_score = self.calculate_risk_score(threats)
        
        # Update skill reputation
        self.update_skill_reputation(skill_path.name, threats, risk_score)
        
        return {
            'skill': skill_path.name,
            'threats': threats,
            'risk_score': risk_score,
            'recommendation': self.get_recommendation(risk_score)
        }
    
    def static_analysis_scan(self, skill_path):
        """Enhanced static code analysis"""
        threats = []
        
        for file_path in skill_path.rglob('*'):
            if file_path.is_file() and file_path.suffix in ['.py', '.js', '.sh', '.bash']:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # Check against database threats
                    threats.extend(self.check_against_db_threats(content, file_path))
                    
                except Exception as e:
                    self.log(f"Error scanning {file_path}: {e}", "ERROR")
        
        return threats
    
    def check_against_db_threats(self, content, file_path):
        """Check content against database threat patterns"""
        threats = []
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM threat_intelligence")
            db_threats = cursor.fetchall()
            
            for threat in db_threats:
                _, source, threat_type, pattern, severity, confidence, _, _ = threat
                
                if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                    threats.append({
                        'type': threat_type,
                        'severity': severity,
                        'confidence': confidence,
                        'file': str(file_path),
                        'pattern': pattern,
                        'source': source
                    })
        
        return threats
    
    def behavioral_analysis_scan(self, skill_path):
        """Behavioral analysis of skill"""
        # Placeholder for behavioral analysis
        return []
    
    def dependency_analysis_scan(self, skill_path):
        """Analyze dependencies for vulnerabilities"""
        threats = []
        
        # Check for suspicious imports/requires
        for file_path in skill_path.rglob('*.py'):
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # Check for risky imports
                risky_imports = ['subprocess', 'os', 'socket', 'urllib', 'requests']
                for imp in risky_imports:
                    if re.search(rf'import\s+{imp}|from\s+{imp}', content):
                        threats.append({
                            'type': 'risky_import',
                            'severity': 'MEDIUM',
                            'confidence': 0.6,
                            'file': str(file_path),
                            'pattern': f'imports {imp}',
                            'description': f'Uses potentially risky module: {imp}'
                        })
                        
            except Exception as e:
                self.log(f"Error in dependency analysis: {e}", "ERROR")
        
        return threats
    
    def ai_powered_analysis(self, skill_path):
        """AI-powered threat analysis"""
        # Placeholder for ML model integration
        threats = []
        
        # Simulate AI analysis
        for file_path in skill_path.rglob('*.py'):
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # Heuristic analysis
                if len(content) > 10000:  # Large files might be obfuscated
                    threats.append({
                        'type': 'suspicious_size',
                        'severity': 'MEDIUM',
                        'confidence': 0.4,
                        'file': str(file_path),
                        'description': 'Unusually large file size'
                    })
                
                # Check for obfuscation
                if content.count('\\x') > 10:  # Hex encoded strings
                    threats.append({
                        'type': 'obfuscation',
                        'severity': 'HIGH',
                        'confidence': 0.8,
                        'file': str(file_path),
                        'description': 'Possible code obfuscation detected'
                    })
                    
            except Exception as e:
                self.log(f"Error in AI analysis: {e}", "ERROR")
        
        return threats
    
    def calculate_risk_score(self, threats):
        """Calculate overall risk score for skill"""
        if not threats:
            return 0.0
        
        severity_weights = {
            'CRITICAL': 10.0,
            'HIGH': 7.0,
            'MEDIUM': 4.0,
            'LOW': 1.0
        }
        
        total_score = 0
        for threat in threats:
            weight = severity_weights.get(threat['severity'], 1.0)
            confidence = threat.get('confidence', 0.5)
            total_score += weight * confidence
        
        # Normalize to 0-100 scale
        return min(100.0, total_score * 2)
    
    def get_recommendation(self, risk_score):
        """Get security recommendation based on risk score"""
        if risk_score >= 80:
            return "🚨 BLOCK: Critical security threats detected"
        elif risk_score >= 60:
            return "⚠️ QUARANTINE: High risk, manual review required"
        elif risk_score >= 30:
            return "⚡ MONITOR: Medium risk, enhanced monitoring recommended"
        else:
            return "✅ ALLOW: Low risk, standard monitoring sufficient"
    
    def update_skill_reputation(self, skill_name, threats, risk_score):
        """Update skill reputation in database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT OR REPLACE INTO skill_reputation 
                (skill_name, trust_score, risk_level, last_scan, threat_count, usage_count)
                VALUES (?, ?, ?, ?, ?, COALESCE((SELECT usage_count FROM skill_reputation WHERE skill_name = ?), 0))
            ''', (
                skill_name,
                max(0, 100 - risk_score),  # Trust score is inverse of risk
                self.get_risk_level(risk_score),
                datetime.now().isoformat(),
                len(threats),
                skill_name
            ))
    
    def get_risk_level(self, risk_score):
        """Convert risk score to risk level"""
        if risk_score >= 80:
            return "CRITICAL"
        elif risk_score >= 60:
            return "HIGH"
        elif risk_score >= 30:
            return "MEDIUM"
        else:
            return "LOW"
    
    def quarantine_skill(self, skill_path, reason):
        """Quarantine dangerous skill"""
        skill_path = Path(skill_path)
        quarantine_path = self.quarantine_dir / f"{skill_path.name}_{int(time.time())}"
        
        try:
            # Move skill to quarantine
            if skill_path.exists():
                skill_path.rename(quarantine_path)
                
                self.log(f"🔒 QUARANTINED: {skill_path.name} -> {quarantine_path}", "SECURITY")
                self.log(f"Reason: {reason}", "SECURITY")
                
                # Create quarantine record
                quarantine_record = {
                    'original_path': str(skill_path),
                    'quarantine_path': str(quarantine_path),
                    'reason': reason,
                    'timestamp': datetime.now().isoformat()
                }
                
                with open(quarantine_path / "QUARANTINE_INFO.json", 'w') as f:
                    json.dump(quarantine_record, f, indent=2)
                
                return True
        except Exception as e:
            self.log(f"Failed to quarantine {skill_path}: {e}", "ERROR")
            return False
    
    def generate_security_dashboard(self):
        """Generate comprehensive security dashboard"""
        self.log("📊 Generating Security Dashboard", "SECURITY")
        
        dashboard = {
            'timestamp': datetime.now().isoformat(),
            'threat_intelligence': self.get_threat_intelligence_status(),
            'skill_security': self.get_skill_security_overview(),
            'recent_events': self.get_recent_security_events(),
            'risk_metrics': self.calculate_risk_metrics(),
            'recommendations': self.get_security_recommendations()
        }
        
        # Save dashboard
        dashboard_file = self.security_dir / "security_dashboard.json"
        with open(dashboard_file, 'w') as f:
            json.dump(dashboard, f, indent=2)
        
        return dashboard
    
    def get_threat_intelligence_status(self):
        """Get threat intelligence status"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM threat_intelligence")
            threat_count = cursor.fetchone()[0]
            
            cursor = conn.execute("SELECT MAX(last_updated) FROM threat_intelligence")
            last_update = cursor.fetchone()[0]
        
        return {
            'total_threats': threat_count,
            'last_update': last_update,
            'sources': len(self.threat_sources)
        }
    
    def get_skill_security_overview(self):
        """Get overview of skill security status"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT risk_level, COUNT(*) 
                FROM skill_reputation 
                GROUP BY risk_level
            """)
            risk_distribution = dict(cursor.fetchall())
            
            cursor = conn.execute("SELECT AVG(trust_score) FROM skill_reputation")
            avg_trust = cursor.fetchone()[0] or 0
        
        return {
            'risk_distribution': risk_distribution,
            'average_trust_score': round(avg_trust, 2),
            'quarantined_skills': len(list(self.quarantine_dir.glob('*')))
        }
    
    def get_recent_security_events(self, hours=24):
        """Get recent security events"""
        since = datetime.now() - timedelta(hours=hours)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT timestamp, event_type, severity, description 
                FROM security_events 
                WHERE timestamp > ? 
                ORDER BY timestamp DESC 
                LIMIT 10
            """, (since.isoformat(),))
            
            return [
                {
                    'timestamp': row[0],
                    'type': row[1],
                    'severity': row[2],
                    'description': row[3]
                }
                for row in cursor.fetchall()
            ]
    
    def calculate_risk_metrics(self):
        """Calculate security risk metrics"""
        with sqlite3.connect(self.db_path) as conn:
            # Count threats by severity
            cursor = conn.execute("""
                SELECT severity, COUNT(*) 
                FROM security_events 
                WHERE timestamp > datetime('now', '-24 hours')
                GROUP BY severity
            """)
            recent_threats = dict(cursor.fetchall())
            
            # Calculate MTTD (placeholder)
            mttd = 15  # 15 minutes average
            
            # Calculate coverage
            total_skills = len(list((self.workspace / "skills").glob('*')))
            scanned_skills = len(list(self.db_path.parent.glob('*.json')))  # Placeholder
            coverage = (scanned_skills / max(total_skills, 1)) * 100
        
        return {
            'recent_threats_24h': recent_threats,
            'mean_time_to_detection_minutes': mttd,
            'security_coverage_percent': round(coverage, 2),
            'false_positive_rate_percent': 2.1  # Placeholder
        }
    
    def get_security_recommendations(self):
        """Get security recommendations"""
        recommendations = []
        
        # Check threat intelligence freshness
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT MAX(last_updated) FROM threat_intelligence")
            last_update = cursor.fetchone()[0]
            
            if last_update:
                update_time = datetime.fromisoformat(last_update)
                if datetime.now() - update_time > timedelta(days=1):
                    recommendations.append({
                        'priority': 'HIGH',
                        'type': 'threat_intelligence',
                        'message': 'Threat intelligence is stale, update recommended'
                    })
        
        # Check quarantine directory
        quarantined_count = len(list(self.quarantine_dir.glob('*')))
        if quarantined_count > 0:
            recommendations.append({
                'priority': 'MEDIUM',
                'type': 'quarantine',
                'message': f'{quarantined_count} skills in quarantine require review'
            })
        
        return recommendations

def main():
    print("🛡️ Advanced AI Agent Security System")
    print("=" * 50)
    
    security = AdvancedSecuritySystem()
    
    if len(sys.argv) < 2:
        print("Usage: python3 advanced_security_system.py <command>")
        print("Commands:")
        print("  update-intel    - Update threat intelligence")
        print("  scan <skill>    - Advanced scan of skill")
        print("  dashboard       - Generate security dashboard")
        print("  full-audit      - Complete security audit")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "update-intel":
        threats = security.enhanced_threat_intelligence()
        print(f"✅ Updated {len(threats)} threat patterns")
    
    elif command == "scan" and len(sys.argv) > 2:
        skill_path = Path(sys.argv[2])
        result = security.advanced_skill_scan(skill_path)
        print(f"📊 Risk Score: {result['risk_score']:.1f}")
        print(f"🎯 Recommendation: {result['recommendation']}")
        
        if result['risk_score'] >= 80:
            security.quarantine_skill(skill_path, "Critical security threats detected")
    
    elif command == "dashboard":
        dashboard = security.generate_security_dashboard()
        print("📊 Security Dashboard Generated")
        print(f"Threats: {dashboard['threat_intelligence']['total_threats']}")
        print(f"Avg Trust: {dashboard['skill_security']['average_trust_score']}")
    
    elif command == "full-audit":
        # Run complete security audit
        security.enhanced_threat_intelligence()
        
        skills_dir = Path("/home/cbrd21/clawd/skills")
        if skills_dir.exists():
            for skill_path in skills_dir.iterdir():
                if skill_path.is_dir():
                    result = security.advanced_skill_scan(skill_path)
                    if result['risk_score'] >= 80:
                        security.quarantine_skill(skill_path, "High risk detected in audit")
        
        dashboard = security.generate_security_dashboard()
        print("🎯 Full Security Audit Complete")
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)

if __name__ == '__main__':
    main()