#!/usr/bin/env python3
"""
Daily Security Audit - Comprehensive security sweep
Updates threat intel + scans all local skills + reports security status
"""

import os
import sys
import subprocess
import json
from pathlib import Path
from datetime import datetime

class SecurityAuditor:
    def __init__(self):
        self.script_dir = Path(__file__).parent
        self.workspace = Path("/home/cbrd21/clawd")
        self.skills_dir = self.workspace / "skills"
        self.update_script = self.script_dir / "update_threats.py"
        self.scanner_script = self.script_dir / "scan_skill.py"
        
    def log(self, message, level="INFO"):
        """Log with timestamp and level"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {level}: {message}")
    
    def run_command(self, cmd, description):
        """Run a command and return success status"""
        self.log(f"Running: {description}")
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                self.log(f"✅ {description} completed successfully", "SUCCESS")
                return True, result.stdout
            else:
                self.log(f"❌ {description} failed: {result.stderr}", "ERROR")
                return False, result.stderr
        except subprocess.TimeoutExpired:
            self.log(f"⏰ {description} timed out", "ERROR")
            return False, "Timeout"
        except Exception as e:
            self.log(f"💥 {description} exception: {e}", "ERROR")
            return False, str(e)
    
    def update_threat_intelligence(self):
        """Update threat intelligence from all sources"""
        self.log("🔄 UPDATING THREAT INTELLIGENCE", "SECURITY")
        
        success, output = self.run_command(
            f"cd {self.workspace} && python3 {self.update_script}",
            "Threat intelligence update"
        )
        
        if success:
            # Extract threat count from output
            lines = output.split('\n')
            for line in lines:
                if "total threats" in line:
                    self.log(f"📊 {line.strip()}", "SECURITY")
                    break
        
        return success
    
    def scan_all_skills(self):
        """Scan all local skills for vulnerabilities"""
        self.log("🔍 SCANNING ALL LOCAL SKILLS", "SECURITY")
        
        if not self.skills_dir.exists():
            self.log("No skills directory found", "WARNING")
            return True, []
        
        threats_found = []
        skills_scanned = 0
        
        for skill_path in self.skills_dir.iterdir():
            if skill_path.is_dir() and not skill_path.name.startswith('.'):
                skills_scanned += 1
                self.log(f"Scanning: {skill_path.name}")
                
                success, output = self.run_command(
                    f"cd {self.workspace} && python3 {self.scanner_script} {skill_path}",
                    f"Security scan: {skill_path.name}"
                )
                
                # Parse scan results for threats
                if not success:  # Exit code 1 = threats found
                    lines = output.split('\n')
                    for line in lines:
                        if "🔴 HIGH:" in line or "🔴 CRITICAL:" in line:
                            threats_found.append(f"{skill_path.name}: {line.strip()}")
                        elif "Critical:" in line or "High:" in line:
                            threats_found.append(f"{skill_path.name}: {line.strip()}")
        
        self.log(f"📋 Scanned {skills_scanned} local skills", "SECURITY")
        return len(threats_found) == 0, threats_found
    
    def check_system_security(self):
        """Basic system security checks"""
        self.log("🛡️ SYSTEM SECURITY CHECKS", "SECURITY")
        
        checks = []
        
        # Check if security scanner is present
        if self.scanner_script.exists():
            checks.append("✅ Security scanner: Present")
        else:
            checks.append("❌ Security scanner: MISSING")
        
        # Check threat cache age
        cache_file = self.script_dir.parent / "references" / "threat_cache.json"
        if cache_file.exists():
            age_hours = (datetime.now().timestamp() - cache_file.stat().st_mtime) / 3600
            if age_hours < 25:  # Less than 25 hours old
                checks.append(f"✅ Threat cache: Fresh ({age_hours:.1f}h old)")
            else:
                checks.append(f"⚠️ Threat cache: Stale ({age_hours:.1f}h old)")
        else:
            checks.append("❌ Threat cache: MISSING")
        
        # Check OpenClaw security
        success, output = self.run_command(
            "openclaw status | grep -E '(security|threat|scan)' || echo 'No security status'",
            "OpenClaw security status"
        )
        
        for check in checks:
            self.log(check, "SECURITY")
        
        return checks
    
    def generate_security_report(self, threat_update_success, skills_safe, skill_threats, system_checks):
        """Generate comprehensive security report"""
        report = []
        report.append("🛡️ DAILY SECURITY AUDIT REPORT")
        report.append(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S EST')}")
        report.append("=" * 50)
        
        # Threat intelligence status
        if threat_update_success:
            report.append("✅ Threat Intelligence: Updated successfully")
        else:
            report.append("❌ Threat Intelligence: Update failed")
        
        # Skills security status
        if skills_safe:
            report.append("✅ Local Skills: All scanned, no threats detected")
        else:
            report.append(f"🚨 Local Skills: {len(skill_threats)} THREATS FOUND")
            for threat in skill_threats[:5]:  # Limit to first 5
                report.append(f"   • {threat}")
            if len(skill_threats) > 5:
                report.append(f"   • ... and {len(skill_threats) - 5} more")
        
        # System checks
        report.append("🔧 System Security:")
        for check in system_checks:
            report.append(f"   {check}")
        
        # Overall status
        if threat_update_success and skills_safe:
            report.append("\n🎯 OVERALL STATUS: SECURE ✅")
        else:
            report.append("\n⚠️ OVERALL STATUS: ATTENTION REQUIRED")
        
        return "\n".join(report)
    
    def run_audit(self):
        """Run complete security audit"""
        self.log("🛡️ STARTING DAILY SECURITY AUDIT", "SECURITY")
        print("=" * 60)
        
        # Step 1: Update threat intelligence
        threat_update_success = self.update_threat_intelligence()
        
        # Step 2: Scan all local skills
        skills_safe, skill_threats = self.scan_all_skills()
        
        # Step 3: System security checks
        system_checks = self.check_system_security()
        
        # Step 4: Generate report
        report = self.generate_security_report(
            threat_update_success, skills_safe, skill_threats, system_checks
        )
        
        print("\n" + report)
        
        # Return exit code based on security status
        if threat_update_success and skills_safe:
            self.log("Security audit completed successfully", "SUCCESS")
            return 0
        else:
            self.log("Security audit found issues requiring attention", "WARNING")
            return 1

def main():
    auditor = SecurityAuditor()
    return auditor.run_audit()

if __name__ == '__main__':
    sys.exit(main())