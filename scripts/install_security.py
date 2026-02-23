#!/usr/bin/env python3
"""
SKSecurity Enterprise - One-Click Security Installation
Installs enterprise-grade AI agent security for OpenClaw and other frameworks
"""

import os
import platform
import sys
import json
import shutil
import subprocess
from pathlib import Path
import sqlite3
from datetime import datetime

class SKSecurityInstaller:
    def __init__(self):
        self.skill_dir = Path(__file__).parent.parent
        self.workspace = Path.cwd()
        self.openclaw_config = None
        self.security_dir = self.workspace / "security"
        
    def detect_environment(self):
        """Detect AI framework and configuration"""
        print("🔍 Detecting AI framework environment...")
        
        # Check for OpenClaw
        openclaw_config_paths = [
            Path.home() / ".openclaw" / "openclaw.json",
            self.workspace / "openclaw.json",
        ]
        if platform.system() != "Windows":
            openclaw_config_paths.append(Path("/etc/openclaw/openclaw.json"))
        
        for config_path in openclaw_config_paths:
            if config_path.exists():
                try:
                    with open(config_path, 'r') as f:
                        self.openclaw_config = json.load(f)
                    print(f"✅ OpenClaw detected: {config_path}")
                    return "openclaw"
                except Exception as e:
                    print(f"⚠️ Error reading OpenClaw config: {e}")
        
        # Check for other frameworks
        if (self.workspace / "autogpt").exists():
            print("✅ AutoGPT detected")
            return "autogpt"
        
        if (self.workspace / "langchain").exists():
            print("✅ LangChain detected")
            return "langchain"
        
        print("⚠️ No specific AI framework detected, using generic installation")
        return "generic"
    
    def create_security_structure(self):
        """Create security directory structure"""
        print("📁 Creating security directory structure...")
        
        # Create main directories
        directories = [
            self.security_dir,
            self.security_dir / "scripts",
            self.security_dir / "config",
            self.security_dir / "logs",
            self.security_dir / "quarantine",
            self.security_dir / "dashboards"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            print(f"   📂 {directory}")
        
        return True
    
    def install_security_scripts(self):
        """Install security scripts"""
        print("🔧 Installing security scripts...")
        
        scripts_to_copy = [
            "advanced_security_system.py",
            "security_dashboard.py", 
            "daily_security_audit.py",
            "update_threats.py",
            "scan_skill.py"
        ]
        
        for script in scripts_to_copy:
            source = self.skill_dir / "scripts" / script
            dest = self.security_dir / "scripts" / script
            
            if source.exists():
                shutil.copy2(source, dest)
                if platform.system() != "Windows":
                    dest.chmod(0o755)
                print(f"   ✅ {script}")
            else:
                print(f"   ⚠️ Missing: {script}")
    
    def create_security_database(self):
        """Initialize security database"""
        print("🗃️ Initializing security database...")
        
        db_path = self.security_dir / "security.db"
        
        with sqlite3.connect(db_path) as conn:
            # Create security events table
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
            
            # Create skill reputation table
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
            
            # Create threat intelligence table
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
            
            # Insert initial log entry
            conn.execute('''
                INSERT INTO security_events 
                (timestamp, event_type, severity, source, description, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                "INSTALLATION",
                "INFO", 
                "installer",
                "SKSecurity Enterprise installed successfully",
                json.dumps({"version": "1.0", "framework": self.detect_environment()})
            ))
        
        print("   ✅ Database initialized")
    
    def create_configuration(self):
        """Create security configuration"""
        print("⚙️ Creating security configuration...")
        
        config = {
            "security": {
                "enabled": True,
                "auto_quarantine": True,
                "risk_threshold": 80,
                "dashboard_port": 8888,
                "threat_sources": [
                    {"name": "Moltbook", "url": "https://www.moltbook.com/security-feed.json", "enabled": True},
                    {"name": "NVD", "url": "https://services.nvd.nist.gov/rest/json/cves/2.0", "enabled": True},
                    {"name": "GitHub", "url": "https://api.github.com/advisories", "enabled": True}
                ],
                "monitoring": {
                    "runtime_monitoring": True,
                    "file_system_monitoring": True,
                    "network_monitoring": True
                },
                "notifications": {
                    "critical_alerts": True,
                    "daily_reports": True,
                    "email_notifications": False
                }
            },
            "installation": {
                "timestamp": datetime.now().isoformat(),
                "version": "1.0",
                "installer_user": os.getenv('USER', 'unknown')
            }
        }
        
        config_file = self.security_dir / "config" / "security.json"
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        print("   ✅ Configuration created")
    
    def setup_automation(self):
        """Setup automated security operations"""
        print("⏰ Setting up automated security operations...")
        
        # Create cron job script
        cron_script = self.security_dir / "scripts" / "security_cron.py"
        
        cron_content = f'''#!/usr/bin/env python3
"""
SKSecurity Automated Operations
Daily security audit and threat intelligence update
"""

import os
import sys
import subprocess
from pathlib import Path

security_dir = Path("{self.security_dir}")
os.chdir(security_dir.parent)

# Run daily security audit
print("🛡️ Running daily SKSecurity audit...")
result = subprocess.run([
    sys.executable,
    str(security_dir / "scripts" / "advanced_security_system.py"),
    "full-audit"
], capture_output=True, text=True)

if result.returncode == 0:
    print("✅ Security audit completed successfully")
else:
    print("❌ Security audit failed:")
    print(result.stderr)
'''
        
        with open(cron_script, 'w') as f:
            f.write(cron_content)

        if platform.system() != "Windows":
            cron_script.chmod(0o755)

        if platform.system() == "Windows":
            self.create_windows_task()
        elif shutil.which("systemctl"):
            self.create_systemd_timer()
        else:
            print("   ⚠️ systemctl not available, manual cron setup required")

        print("   ✅ Automation configured")
    
    def create_systemd_timer(self):
        """Create systemd timer for automated operations"""
        try:
            # Create service file
            service_content = f'''[Unit]
Description=SKSecurity Daily Audit
After=network.target

[Service]
Type=oneshot
User={os.getenv('USER', 'root')}
WorkingDirectory={self.workspace}
ExecStart={sys.executable} {self.security_dir}/scripts/security_cron.py
'''
            
            service_file = Path.home() / ".config" / "systemd" / "user" / "sksecurity-audit.service"
            service_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(service_file, 'w') as f:
                f.write(service_content)
            
            # Create timer file
            timer_content = '''[Unit]
Description=SKSecurity Daily Audit Timer
Requires=sksecurity-audit.service

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
'''
            
            timer_file = service_file.parent / "sksecurity-audit.timer"
            with open(timer_file, 'w') as f:
                f.write(timer_content)
            
            # Enable timer
            subprocess.run(['systemctl', '--user', 'daemon-reload'], check=False)
            subprocess.run(['systemctl', '--user', 'enable', 'sksecurity-audit.timer'], check=False)
            subprocess.run(['systemctl', '--user', 'start', 'sksecurity-audit.timer'], check=False)
            
            print("   ✅ systemd timer installed and started")
            
        except Exception as e:
            print(f"   ⚠️ systemd setup failed: {e}")

    def create_windows_task(self):
        """Create a Windows Task Scheduler entry for daily security audits."""
        try:
            cron_script = self.security_dir / "scripts" / "security_cron.py"
            cmd_line = f'"{sys.executable}" "{cron_script}"'
            proc = subprocess.run(
                [
                    "schtasks", "/Create",
                    "/SC", "DAILY",
                    "/TN", "SKSecurityAudit",
                    "/TR", cmd_line,
                    "/ST", "06:00",
                    "/F",
                ],
                capture_output=True, text=True, check=False,
            )
            if proc.returncode == 0:
                print("   ✅ Windows scheduled task installed")
            else:
                print(f"   ⚠️ schtasks failed: {proc.stderr.strip()}")
        except Exception as e:
            print(f"   ⚠️ Windows task setup failed: {e}")

    def create_dashboard_launcher(self):
        """Create dashboard launcher script"""
        print("🖥️ Creating dashboard launcher...")
        
        launcher_script = self.security_dir / "launch_dashboard.py"
        
        launcher_content = f'''#!/usr/bin/env python3
"""
SKSecurity Dashboard Launcher
Launch the security operations center dashboard
"""

import os
import sys
from pathlib import Path

# Add security scripts to path
security_scripts = Path("{self.security_dir}") / "scripts"
sys.path.insert(0, str(security_scripts))

# Change to security directory
os.chdir("{self.security_dir}")

# Import and run dashboard
from security_dashboard import main

if __name__ == '__main__':
    print("🛡️ Starting SKSecurity Dashboard")
    print("📍 http://localhost:8888")
    print("Press Ctrl+C to stop")
    main()
'''
        
        with open(launcher_script, 'w') as f:
            f.write(launcher_content)

        if platform.system() != "Windows":
            launcher_script.chmod(0o755)
        
        print("   ✅ Dashboard launcher created")
    
    def run_initial_security_scan(self):
        """Run initial security scan"""
        print("🔍 Running initial security scan...")
        
        try:
            result = subprocess.run([
                sys.executable,
                str(self.security_dir / "scripts" / "advanced_security_system.py"),
                "update-intel"
            ], capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                print("   ✅ Threat intelligence updated")
            else:
                print("   ⚠️ Initial scan had issues (will retry automatically)")
                
        except subprocess.TimeoutExpired:
            print("   ⚠️ Initial scan timed out (will retry automatically)")
        except Exception as e:
            print(f"   ⚠️ Initial scan error: {e}")
    
    def print_success_message(self):
        """Print installation success message"""
        print("\n" + "="*60)
        print("🎉 SKSecurity Enterprise Installation Complete!")
        print("="*60)
        print()
        print("🛡️ Your AI agents are now protected by enterprise-grade security!")
        print()
        print("📍 Security Dashboard:")
        print(f"   python3 {self.security_dir}/launch_dashboard.py")
        print("   Then visit: http://localhost:8888")
        print()
        print("🔧 Manual Security Scan:")
        print(f"   python3 {self.security_dir}/scripts/advanced_security_system.py scan <path>")
        print()
        print("📊 Generate Security Report:")
        print(f"   python3 {self.security_dir}/scripts/advanced_security_system.py dashboard")
        print()
        print("⏰ Automated Operations:")
        print("   Daily security audits run automatically at 6:00 AM")
        if platform.system() == "Windows":
            print("   Check status: schtasks /Query /TN SKSecurityAudit")
        else:
            print("   Check status: systemctl --user status sksecurity-audit.timer")
        print()
        print("📁 Security Files:")
        print(f"   Configuration: {self.security_dir}/config/security.json")
        print(f"   Database: {self.security_dir}/security.db")
        print(f"   Logs: {self.security_dir}/logs/")
        print(f"   Quarantine: {self.security_dir}/quarantine/")
        print()
        print("🌐 Community Support:")
        print("   GitHub: https://github.com/smilinTux/SKSecurity")
        print("   Moltbook: https://moltbook.com/community/security")
        print()
        print("✨ Welcome to enterprise-grade AI security!")
    
    def install(self):
        """Run complete installation"""
        print("🛡️ SKSecurity Enterprise Installer")
        print("="*50)
        
        try:
            framework = self.detect_environment()
            self.create_security_structure()
            self.install_security_scripts()
            self.create_security_database()
            self.create_configuration()
            self.setup_automation()
            self.create_dashboard_launcher()
            self.run_initial_security_scan()
            self.print_success_message()
            
            return True
            
        except Exception as e:
            print(f"\n❌ Installation failed: {e}")
            print("Please check the error above and try again.")
            return False

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print("SKSecurity Enterprise Installer")
        print()
        print("Usage: python3 install_security.py")
        print()
        print("This installer will:")
        print("  • Detect your AI framework (OpenClaw, AutoGPT, etc.)")
        print("  • Install enterprise security components")
        print("  • Setup automated daily security audits")
        print("  • Configure security dashboard")
        print("  • Run initial threat intelligence update")
        print()
        return
    
    installer = SKSecurityInstaller()
    success = installer.install()
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()