"""
SKSecurity Scanner - Core Security Scanning Engine
Multi-layered security analysis for AI agents and skills
"""

import os
import re
import json
import hashlib
import mimetypes
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Union
import yaml

from .intelligence import ThreatIntelligence
from .database import SecurityDatabase, SecurityEvent

@dataclass
class ThreatMatch:
    """Individual threat pattern match."""
    threat_type: str
    severity: str
    confidence: float
    file_path: str
    line_number: int
    pattern: str
    context: str
    source: str = "scanner"

@dataclass  
class ScanResult:
    """Security scan results."""
    target_path: str
    scan_timestamp: str
    risk_score: float
    threat_count: int
    files_scanned: int
    threats: List[ThreatMatch]
    recommendations: List[str]
    summary: str
    quarantined: bool = False
    quarantine_path: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)
    
    def to_yaml(self) -> str:
        """Convert to YAML string."""
        return yaml.dump(self.to_dict(), default_flow_style=False)
    
    def format_report(self) -> str:
        """Format as human-readable report."""
        report = []
        
        # Header
        report.append("🛡️ SKSecurity Scan Report")
        report.append("=" * 50)
        report.append(f"📁 Target: {self.target_path}")
        report.append(f"⏰ Scanned: {self.scan_timestamp}")
        report.append(f"📊 Risk Score: {self.risk_score:.1f}/100")
        report.append(f"📄 Files Scanned: {self.files_scanned}")
        report.append(f"🚨 Threats Found: {self.threat_count}")
        report.append("")
        
        # Overall status
        if self.risk_score >= 80:
            status = f"🚨 CRITICAL: {self.summary}"
        elif self.risk_score >= 60:
            status = f"⚠️ HIGH RISK: {self.summary}"  
        elif self.risk_score >= 30:
            status = f"⚡ MEDIUM RISK: {self.summary}"
        else:
            status = f"✅ LOW RISK: {self.summary}"
        
        report.append(f"🎯 Status: {status}")
        report.append("")
        
        # Quarantine status
        if self.quarantined:
            report.append(f"🔒 QUARANTINED: {self.quarantine_path}")
            report.append("")
        
        # Threat details
        if self.threats:
            report.append("📋 Threat Details:")
            report.append("-" * 30)
            
            # Group by severity
            critical = [t for t in self.threats if t.severity == 'CRITICAL']
            high = [t for t in self.threats if t.severity == 'HIGH']
            medium = [t for t in self.threats if t.severity == 'MEDIUM']
            low = [t for t in self.threats if t.severity == 'LOW']
            
            for severity_group, threats in [
                ('CRITICAL', critical), 
                ('HIGH', high),
                ('MEDIUM', medium),
                ('LOW', low)
            ]:
                if threats:
                    report.append(f"\n🔴 {severity_group} ({len(threats)} threats):")
                    for threat in threats[:5]:  # Limit to 5 per severity
                        report.append(f"   • {threat.threat_type} in {Path(threat.file_path).name}")
                        report.append(f"     Line {threat.line_number}: {threat.context[:80]}...")
                        if threat.confidence < 0.8:
                            report.append(f"     Confidence: {threat.confidence:.1%}")
                    
                    if len(threats) > 5:
                        report.append(f"     ... and {len(threats) - 5} more")
        else:
            report.append("✅ No security threats detected")
        
        report.append("")
        
        # Recommendations
        if self.recommendations:
            report.append("💡 Recommendations:")
            report.append("-" * 20)
            for i, rec in enumerate(self.recommendations, 1):
                report.append(f"{i}. {rec}")
            report.append("")
        
        # Footer
        report.append("🌐 Powered by SKSecurity Enterprise")
        report.append("   GitHub: https://github.com/smilinTux/SKSecurity")
        
        return "\n".join(report)

class SecurityScanner:
    """Multi-layered AI agent security scanner."""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.threat_intel = ThreatIntelligence(config=config)
        self.database = SecurityDatabase(config=config) if config else None
        
        # Scanning configuration
        self.max_file_size = self.config.get('scanner.max_file_size', 10 * 1024 * 1024)  # 10MB
        self.skip_binaries = self.config.get('scanner.skip_binaries', True)
        self.skip_extensions = set(self.config.get('scanner.skip_extensions', [
            '.pyc', '.pyo', '.so', '.dll', '.exe', '.bin', '.jpg', '.png', '.gif',
            '.zip', '.tar', '.gz', '.bz2', '.7z', '.pdf', '.doc', '.docx'
        ]))
        
        # Risk scoring weights
        self.severity_weights = {
            'CRITICAL': 25.0,
            'HIGH': 15.0, 
            'MEDIUM': 8.0,
            'LOW': 3.0
        }
    
    def scan(self, target_path: Union[str, Path]) -> ScanResult:
        """Perform comprehensive security scan."""
        target_path = Path(target_path)
        scan_start = datetime.now()
        
        if not target_path.exists():
            raise ValueError(f"Target path does not exist: {target_path}")
        
        # Initialize scan state
        threats = []
        files_scanned = 0
        
        # Scan files
        if target_path.is_file():
            file_threats = self._scan_file(target_path)
            threats.extend(file_threats)
            files_scanned = 1
        else:
            # Scan directory recursively
            for file_path in self._get_scannable_files(target_path):
                try:
                    file_threats = self._scan_file(file_path)
                    threats.extend(file_threats)
                    files_scanned += 1
                except Exception as e:
                    # Log error but continue scanning
                    if self.database:
                        self.database.log_event(
                            SecurityEvent(
                                timestamp=datetime.now(),
                                event_type="SCAN_ERROR",
                                severity="WARNING", 
                                source="scanner",
                                description=f"Error scanning {file_path}: {e}",
                                metadata={"file_path": str(file_path), "error": str(e)}
                            )
                        )
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(threats)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(threats, risk_score)
        
        # Create summary
        summary = self._generate_summary(threats, risk_score, files_scanned)
        
        # Create scan result
        result = ScanResult(
            target_path=str(target_path),
            scan_timestamp=scan_start.isoformat(),
            risk_score=risk_score,
            threat_count=len(threats),
            files_scanned=files_scanned,
            threats=threats,
            recommendations=recommendations,
            summary=summary
        )
        
        # Log scan event
        if self.database:
            self.database.log_event(
                SecurityEvent(
                    timestamp=scan_start,
                    event_type="SECURITY_SCAN",
                    severity="INFO" if risk_score < 60 else "HIGH" if risk_score < 80 else "CRITICAL",
                    source="scanner",
                    description=f"Security scan completed: {summary}",
                    metadata={
                        "target_path": str(target_path),
                        "risk_score": risk_score,
                        "threat_count": len(threats),
                        "files_scanned": files_scanned
                    }
                )
            )
        
        return result
    
    def _get_scannable_files(self, directory: Path) -> List[Path]:
        """Get list of files to scan, filtering out binaries and large files."""
        scannable_files = []
        
        for file_path in directory.rglob('*'):
            if not file_path.is_file():
                continue
            
            # Skip if too large
            if file_path.stat().st_size > self.max_file_size:
                continue
            
            # Skip by extension
            if file_path.suffix.lower() in self.skip_extensions:
                continue
            
            # Skip binary files if configured
            if self.skip_binaries and self._is_binary_file(file_path):
                continue
            
            scannable_files.append(file_path)
        
        return scannable_files
    
    def _is_binary_file(self, file_path: Path) -> bool:
        """Check if file is binary."""
        try:
            # Check MIME type
            mime_type, _ = mimetypes.guess_type(str(file_path))
            if mime_type and not mime_type.startswith('text/'):
                return True
            
            # Check for null bytes (binary indicator)
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)  # Read first 1KB
                if b'\x00' in chunk:
                    return True
            
            return False
        except:
            return True  # Assume binary if can't read
    
    def _scan_file(self, file_path: Path) -> List[ThreatMatch]:
        """Scan individual file for security threats."""
        threats = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return threats  # Skip files we can't read
        
        # Get threat patterns from intelligence
        threat_patterns = self.threat_intel.get_patterns()
        
        # Scan against each pattern
        for pattern_data in threat_patterns:
            pattern = pattern_data.get('pattern', '')
            if not pattern:
                continue
            
            # Find matches
            matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))
            
            for match in matches:
                # Get line number and context
                line_start = content.rfind('\n', 0, match.start()) + 1
                line_end = content.find('\n', match.end())
                if line_end == -1:
                    line_end = len(content)
                
                line_content = content[line_start:line_end]
                line_number = content[:match.start()].count('\n') + 1
                
                # Skip if clearly just documentation/comments
                if self._is_documentation_context(line_content):
                    continue
                
                # Create threat match
                threat = ThreatMatch(
                    threat_type=pattern_data.get('type', 'unknown'),
                    severity=pattern_data.get('severity', 'MEDIUM'),
                    confidence=pattern_data.get('confidence', 0.8),
                    file_path=str(file_path),
                    line_number=line_number,
                    pattern=pattern,
                    context=line_content.strip(),
                    source=pattern_data.get('source', 'threat_intelligence')
                )
                
                threats.append(threat)
        
        # Additional heuristic analysis
        threats.extend(self._heuristic_analysis(file_path, content))
        
        return threats
    
    def _is_documentation_context(self, line: str) -> bool:
        """Check if line appears to be documentation/comments."""
        stripped = line.strip()
        
        # Check for comment patterns
        comment_patterns = [
            r'^\s*#.*example',
            r'^\s*#.*demo', 
            r'^\s*//.*example',
            r'^\s*\*.*example',
            r'^\s*""".*example',
            r'^\s*\'\'\'.*example'
        ]
        
        for pattern in comment_patterns:
            if re.search(pattern, stripped, re.IGNORECASE):
                return True
        
        return False
    
    def _heuristic_analysis(self, file_path: Path, content: str) -> List[ThreatMatch]:
        """Additional heuristic-based threat analysis."""
        threats = []
        
        # Check for suspicious file size vs content ratio
        if len(content) > 50000 and content.count('\n') < 100:
            # Very long lines might indicate obfuscation
            threats.append(ThreatMatch(
                threat_type='obfuscation',
                severity='MEDIUM',
                confidence=0.6,
                file_path=str(file_path),
                line_number=1,
                pattern='long_lines_heuristic',
                context='Unusually long lines detected',
                source='heuristic'
            ))
        
        # Check for high entropy (possible encoded/encrypted content)
        entropy = self._calculate_entropy(content[:5000])  # First 5KB
        if entropy > 7.5:  # High entropy threshold
            threats.append(ThreatMatch(
                threat_type='high_entropy',
                severity='MEDIUM',
                confidence=0.5,
                file_path=str(file_path),
                line_number=1,
                pattern='entropy_analysis',
                context=f'High entropy content detected (entropy: {entropy:.2f})',
                source='heuristic'
            ))
        
        # Check for suspicious imports/requires concentration
        import_patterns = [
            r'import\s+(os|sys|subprocess|socket|urllib)',
            r'require\([\'\"](fs|child_process|net|http)[\'\"]\)',
            r'from\s+(os|sys|subprocess|socket|urllib)'
        ]
        
        import_count = 0
        for pattern in import_patterns:
            import_count += len(re.findall(pattern, content, re.IGNORECASE))
        
        if import_count > 10:  # Many suspicious imports
            threats.append(ThreatMatch(
                threat_type='suspicious_imports',
                severity='MEDIUM',
                confidence=0.7,
                file_path=str(file_path),
                line_number=1,
                pattern='import_analysis',
                context=f'{import_count} potentially risky imports detected',
                source='heuristic'
            ))
        
        return threats
    
    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of string."""
        import math

        if not data:
            return 0.0

        char_counts: dict[str, int] = {}
        for char in data:
            char_counts[char] = char_counts.get(char, 0) + 1

        entropy = 0.0
        data_len = len(data)
        for count in char_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy
    
    def _calculate_risk_score(self, threats: List[ThreatMatch]) -> float:
        """Calculate overall risk score from threats."""
        if not threats:
            return 0.0
        
        total_score = 0.0
        
        for threat in threats:
            # Base score from severity
            base_score = self.severity_weights.get(threat.severity, 5.0)
            
            # Adjust by confidence
            adjusted_score = base_score * threat.confidence
            
            total_score += adjusted_score
        
        # Normalize to 0-100 scale with diminishing returns
        # Using logarithmic scaling to prevent extremely high scores
        import math
        risk_score = min(100.0, (math.log(total_score + 1) / math.log(101)) * 100)
        
        return round(risk_score, 1)
    
    def _generate_recommendations(self, threats: List[ThreatMatch], risk_score: float) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        
        if risk_score >= 80:
            recommendations.append("CRITICAL: Immediate quarantine recommended - high-risk threats detected")
            recommendations.append("Do not deploy this code in production environments")
        elif risk_score >= 60:
            recommendations.append("HIGH RISK: Manual security review required before deployment")
            recommendations.append("Consider running in isolated/sandboxed environment")
        elif risk_score >= 30:
            recommendations.append("MEDIUM RISK: Enhanced monitoring recommended during execution")
            recommendations.append("Review flagged code sections for potential issues")
        else:
            recommendations.append("LOW RISK: Standard security monitoring sufficient")
        
        # Specific recommendations based on threat types
        threat_types = {threat.threat_type for threat in threats}
        
        if 'code_injection' in threat_types or 'command_injection' in threat_types:
            recommendations.append("Review all dynamic code execution patterns")
            recommendations.append("Implement input validation and sanitization")
        
        if 'hardcoded_secrets' in threat_types:
            recommendations.append("Move secrets to environment variables or secure vault")
            recommendations.append("Audit version control history for exposed secrets")
        
        if 'obfuscation' in threat_types:
            recommendations.append("Investigate obfuscated code for malicious intent")
            recommendations.append("Request source code in readable format")
        
        # Always add general recommendations
        recommendations.append("Keep security intelligence up to date")
        recommendations.append("Enable continuous monitoring during execution")
        
        return recommendations
    
    def _generate_summary(self, threats: List[ThreatMatch], risk_score: float, files_scanned: int) -> str:
        """Generate scan summary."""
        if not threats:
            return f"No security threats detected in {files_scanned} files"
        
        # Count by severity
        severity_counts = {}
        for threat in threats:
            severity_counts[threat.severity] = severity_counts.get(threat.severity, 0) + 1
        
        severity_parts = []
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                severity_parts.append(f"{count} {severity.lower()}")
        
        threats_desc = ", ".join(severity_parts)
        
        if risk_score >= 80:
            action = "requires immediate quarantine"
        elif risk_score >= 60:
            action = "requires manual review"
        elif risk_score >= 30:
            action = "requires enhanced monitoring"
        else:
            action = "cleared for standard deployment"
        
        return f"Found {len(threats)} threats ({threats_desc}) in {files_scanned} files, {action}"