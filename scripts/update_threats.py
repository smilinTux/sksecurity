#!/usr/bin/env python3
"""
Daily threat intelligence updater for security scanner
Fetches from Moltbook + other security sources and updates threat cache
"""

import json
import urllib.request
import urllib.error
from pathlib import Path
import time
from datetime import datetime

class ThreatUpdater:
    def __init__(self):
        self.script_dir = Path(__file__).parent
        self.cache_file = self.script_dir.parent / "references" / "threat_cache.json"
        self.sources = [
            {
                "name": "Moltbook",
                "url": "https://www.moltbook.com/security-feed.json",
                "priority": 1
            },
            {
                "name": "Moltbook Security API", 
                "url": "https://api.moltbook.com/security/threats.json",
                "priority": 2
            }
        ]
        
    def fetch_from_source(self, source):
        """Fetch threats from a single source"""
        try:
            print(f"🔄 Fetching from {source['name']}: {source['url']}")
            
            with urllib.request.urlopen(source['url'], timeout=15) as response:
                if response.getcode() == 200:
                    data = response.read().decode('utf-8')
                    threats = json.loads(data)
                    
                    threat_count = len(threats.get('threats', []))
                    print(f"✅ {source['name']}: {threat_count} threats")
                    return threats
                else:
                    print(f"❌ {source['name']}: HTTP {response.getcode()}")
                    return None
                    
        except urllib.error.HTTPError as e:
            print(f"❌ {source['name']}: HTTP {e.code}")
            return None
        except Exception as e:
            print(f"❌ {source['name']}: {e}")
            return None
    
    def merge_threats(self, threat_databases):
        """Merge threats from multiple sources"""
        merged = {
            "last_updated": datetime.now().isoformat(),
            "version": "1.1",
            "sources": [],
            "threats": []
        }
        
        seen_patterns = set()
        
        for db in threat_databases:
            if not db:
                continue
                
            source_name = db.get('source', 'Unknown')
            merged['sources'].append(source_name)
            
            for threat in db.get('threats', []):
                pattern = threat.get('pattern', '')
                
                # Avoid duplicates
                if pattern in seen_patterns:
                    continue
                    
                seen_patterns.add(pattern)
                merged['threats'].append(threat)
        
        return merged
    
    def load_fallback_threats(self):
        """Load enhanced fallback threat patterns"""
        return {
            "source": "Built-in Enhanced",
            "threats": [
                {"type": "code_injection", "pattern": r"eval\s*\(", "severity": "CRITICAL"},
                {"type": "command_injection", "pattern": r"os\.system\s*\(", "severity": "CRITICAL"}, 
                {"type": "shell_injection", "pattern": r"subprocess\.(call|run|Popen).*shell=True", "severity": "HIGH"},
                {"type": "path_traversal", "pattern": r"\.\./", "severity": "MEDIUM"},
                {"type": "hardcoded_secrets", "pattern": r"(password|token|key|secret|api_key)\s*=\s*['\"][^'\"]{8,}['\"]", "severity": "HIGH"},
                {"type": "unsafe_yaml", "pattern": r"yaml\.load\(", "severity": "MEDIUM"},
                {"type": "unsafe_pickle", "pattern": r"pickle\.loads?\(", "severity": "HIGH"},
                {"type": "sql_injection", "pattern": r"execute\(.*%.*\)", "severity": "HIGH"},
                {"type": "xss_potential", "pattern": r"innerHTML\s*=|document\.write\(", "severity": "MEDIUM"},
                {"type": "crypto_weakness", "pattern": r"(md5|sha1)\(", "severity": "LOW"},
                {"type": "insecure_random", "pattern": r"random\.random\(|Math\.random\(", "severity": "LOW"},
                {"type": "debug_mode", "pattern": r"DEBUG\s*=\s*True|debug\s*=\s*true", "severity": "MEDIUM"},
                {"type": "insecure_protocol", "pattern": r"http://(?!localhost|127\.0\.0\.1)", "severity": "MEDIUM"},
                {"type": "weak_crypto", "pattern": r"(DES|RC4|3DES)", "severity": "HIGH"},
                {"type": "unsafe_deserialization", "pattern": r"json\.loads.*input|loads\(.*request", "severity": "MEDIUM"},
                {"type": "buffer_overflow", "pattern": r"strcpy\s*\(|strcat\s*\(", "severity": "HIGH"},
                {"type": "format_string", "pattern": r"printf\s*\([^,)]*%", "severity": "HIGH"},
                {"type": "race_condition", "pattern": r"time\.sleep\(0\)|threading\..*\.start\(\)", "severity": "MEDIUM"},
                {"type": "privilege_escalation", "pattern": r"sudo|setuid|chmod\s+[0-7]*7[0-7]*", "severity": "HIGH"},
                {"type": "backdoor_pattern", "pattern": r"reverse_shell|nc\s+-e|/bin/sh", "severity": "CRITICAL"}
            ]
        }
    
    def update(self):
        """Main update function"""
        print("🛡️ Daily Security Threat Intelligence Update")
        print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 50)
        
        threat_databases = []
        
        # Fetch from all sources
        for source in self.sources:
            threats = self.fetch_from_source(source)
            if threats:
                threat_databases.append(threats)
        
        # Always include enhanced fallback
        threat_databases.append(self.load_fallback_threats())
        
        # Merge all sources
        merged = self.merge_threats(threat_databases)
        
        # Write to cache file
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(merged, f, indent=2)
            
            print(f"\n✅ Updated threat cache: {len(merged['threats'])} total threats")
            print(f"📍 Location: {self.cache_file}")
            print(f"🌐 Sources: {', '.join(merged['sources'])}")
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to write cache: {e}")
            return False

def main():
    updater = ThreatUpdater()
    success = updater.update()
    
    if success:
        print("\n🎯 Security scanner ready with latest threat intel!")
    else:
        print("\n⚠️ Update failed - using existing cache")
    
    return 0 if success else 1

if __name__ == '__main__':
    exit(main())