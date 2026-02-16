#!/usr/bin/env python3
"""
Security Scanner for Public Skills
Fetches latest threat intel from Moltbook and scans skills for vulnerabilities
"""

import os
import sys
import json
import hashlib
import subprocess
import re
import urllib.request
import urllib.error
from pathlib import Path
import tempfile
import zipfile

class SecurityScanner:
    def __init__(self):
        self.threat_db = {}
        self.scan_results = {}
        self.moltbook_url = "https://www.moltbook.com"
        
    def update_threat_intel(self):
        """Fetch latest security intelligence from Moltbook"""
        print("🔄 Updating threat intelligence from Moltbook...")
        
        try:
            # Fetch Moltbook security feed
            with urllib.request.urlopen(f"{self.moltbook_url}/security-feed.json", timeout=10) as response:
                if response.getcode() == 200:
                    data = response.read().decode('utf-8')
                    self.threat_db = json.loads(data)
                    print(f"✅ Loaded {len(self.threat_db.get('threats', []))} threat signatures")
                else:
                    print(f"⚠️ Moltbook security feed unavailable (HTTP {response.getcode()})")
                    # Load cached threats if available
                    self.load_cached_threats()
                
        except Exception as e:
            print(f"⚠️ Failed to fetch from Moltbook: {e}")
            self.load_cached_threats()
    
    def load_cached_threats(self):
        """Load cached threat signatures"""
        cache_file = Path(__file__).parent.parent / "references" / "threat_cache.json"
        if cache_file.exists():
            with open(cache_file, 'r') as f:
                self.threat_db = json.load(f)
            print(f"📋 Loaded {len(self.threat_db.get('threats', []))} cached threat signatures")
        else:
            # Fallback to basic threat patterns
            self.threat_db = {
                "threats": [
                    {"type": "code_injection", "pattern": r"eval\s*\(", "severity": "HIGH"},
                    {"type": "command_injection", "pattern": r"os\.system\s*\(", "severity": "HIGH"}, 
                    {"type": "shell_injection", "pattern": r"subprocess\.(call|run|Popen).*shell=True", "severity": "HIGH"},
                    {"type": "path_traversal", "pattern": r"\.\./", "severity": "MEDIUM"},
                    {"type": "hardcoded_secrets", "pattern": r"(password|token|key|secret)\s*=\s*['\"][^'\"]+['\"]", "severity": "HIGH"},
                    {"type": "unsafe_yaml", "pattern": r"yaml\.load\(", "severity": "MEDIUM"},
                    {"type": "unsafe_pickle", "pattern": r"pickle\.loads?\(", "severity": "HIGH"},
                    {"type": "sql_injection", "pattern": r"execute\(.*%.*\)", "severity": "HIGH"}
                ]
            }
            print(f"🛡️ Using {len(self.threat_db['threats'])} default security patterns")
    
    def scan_file(self, file_path):
        """Scan a single file for security vulnerabilities"""
        threats_found = []
        
        # Skip documentation files that contain examples
        if file_path.suffix.lower() in ['.md', '.txt', '.rst'] or 'readme' in file_path.name.lower():
            return threats_found
        
        # Skip the threat cache itself
        if 'threat_cache.json' in file_path.name:
            return threats_found
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check against threat patterns
            for threat in self.threat_db.get('threats', []):
                pattern = threat.get('pattern', '')
                matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))
                
                for match in matches:
                    # Skip if it's clearly just an example or comment
                    line_start = content.rfind('\n', 0, match.start()) + 1
                    line_end = content.find('\n', match.end())
                    if line_end == -1:
                        line_end = len(content)
                    line = content[line_start:line_end]
                    
                    # Skip commented examples or documentation
                    if re.search(r'^\s*#.*example|^\s*#.*demo|^\s*//.*example|^\s*\*.*example', line, re.IGNORECASE):
                        continue
                    
                    threats_found.append({
                        'type': threat.get('type', 'unknown'),
                        'severity': threat.get('severity', 'MEDIUM'),
                        'file': str(file_path),
                        'pattern': pattern,
                        'line': line.strip()
                    })
            
            # Additional security checks for code files only
            if file_path.suffix in ['.py', '.js', '.sh', '.bash']:
                threats_found.extend(self.deep_code_scan(content, file_path))
                
        except Exception as e:
            print(f"⚠️ Error scanning {file_path}: {e}")
            
        return threats_found
    
    def deep_code_scan(self, content, file_path):
        """Perform deeper security analysis on code files"""
        threats = []
        
        # Check for suspicious network calls
        if re.search(r'requests\.(get|post).*verify=False', content):
            threats.append({
                'type': 'ssl_verification_disabled',
                'severity': 'HIGH',
                'file': str(file_path),
                'pattern': 'SSL verification disabled'
            })
        
        # Check for dangerous file operations
        if re.search(r'open\s*\(.*["\']w["\'].*\)', content) and '../' in content:
            threats.append({
                'type': 'unsafe_file_write',
                'severity': 'MEDIUM', 
                'file': str(file_path),
                'pattern': 'Potential path traversal in file write'
            })
        
        # Check for exec/eval patterns
        if re.search(r'exec\s*\(|eval\s*\(', content):
            threats.append({
                'type': 'dynamic_code_execution',
                'severity': 'CRITICAL',
                'file': str(file_path), 
                'pattern': 'Dynamic code execution detected'
            })
        
        return threats
    
    def scan_skill(self, skill_path):
        """Scan an entire skill for security vulnerabilities"""
        skill_path = Path(skill_path)
        print(f"🔍 Scanning skill: {skill_path.name}")
        
        all_threats = []
        files_scanned = 0
        
        # Scan all files in the skill
        for file_path in skill_path.rglob('*'):
            if file_path.is_file() and not file_path.name.startswith('.'):
                threats = self.scan_file(file_path)
                all_threats.extend(threats)
                files_scanned += 1
        
        # Categorize results
        critical_threats = [t for t in all_threats if t['severity'] == 'CRITICAL']
        high_threats = [t for t in all_threats if t['severity'] == 'HIGH'] 
        medium_threats = [t for t in all_threats if t['severity'] == 'MEDIUM']
        low_threats = [t for t in all_threats if t['severity'] == 'LOW']
        
        results = {
            'skill_name': skill_path.name,
            'files_scanned': files_scanned,
            'threats_found': len(all_threats),
            'critical': len(critical_threats),
            'high': len(high_threats),
            'medium': len(medium_threats),
            'low': len(low_threats),
            'threats': all_threats,
            'safe': len(all_threats) == 0
        }
        
        return results
    
    def print_results(self, results):
        """Print formatted scan results"""
        skill_name = results['skill_name']
        safe = results['safe']
        
        print(f"\n{'='*50}")
        print(f"Security Scan Results: {skill_name}")
        print(f"{'='*50}")
        print(f"Files scanned: {results['files_scanned']}")
        print(f"Threats found: {results['threats_found']}")
        
        if safe:
            print("✅ SAFE - No security threats detected")
            return True
        else:
            print("🚨 THREATS DETECTED:")
            print(f"  Critical: {results['critical']}")
            print(f"  High: {results['high']}")
            print(f"  Medium: {results['medium']}")
            print(f"  Low: {results['low']}")
            
            # Show details for critical and high threats
            for threat in results['threats']:
                if threat['severity'] in ['CRITICAL', 'HIGH']:
                    print(f"\n🔴 {threat['severity']}: {threat['type']}")
                    print(f"   File: {threat['file']}")
                    print(f"   Pattern: {threat['pattern']}")
                    if 'line' in threat:
                        print(f"   Code: {threat['line'][:80]}{'...' if len(threat['line']) > 80 else ''}")
            
            # Only block on CRITICAL and HIGH threats
            blocking_threats = results['critical'] + results['high']
            if blocking_threats > 0:
                print(f"\n❌ BLOCKING INSTALLATION - {blocking_threats} critical/high threats found")
                return False
            else:
                print(f"\n⚠️ WARNINGS ONLY - Medium/low threats detected, installation allowed")
                return True

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 scan_skill.py <skill_path>")
        sys.exit(1)
    
    skill_path = sys.argv[1]
    if not os.path.exists(skill_path):
        print(f"Error: Skill path '{skill_path}' does not exist")
        sys.exit(1)
    
    scanner = SecurityScanner()
    scanner.update_threat_intel()
    
    results = scanner.scan_skill(skill_path)
    is_safe = scanner.print_results(results)
    
    # Exit with appropriate code
    sys.exit(0 if is_safe else 1)

if __name__ == '__main__':
    main()