"""SKSecurity Enterprise - Threat Intelligence Module"""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import json
import requests


@dataclass
class ThreatSource:
    """Represents a threat intelligence source."""
    name: str
    url: str
    enabled: bool = True
    priority: int = 1
    last_fetch: Optional[datetime] = None
    
    def fetch(self) -> List[Dict]:
        """Fetch threats from this source."""
        if not self.enabled:
            return []
        try:
            response = requests.get(self.url, timeout=10)
            response.raise_for_status()
            self.last_fetch = datetime.now()
            return response.json() if response.text else []
        except Exception as e:
            print(f"Error fetching from {self.name}: {e}")
            return []


@dataclass
class ThreatIndicator:
    """Represents a threat indicator (IOC)."""
    type: str  # 'ip', 'domain', 'hash', 'signature'
    value: str
    severity: str = 'medium'  # 'low', 'medium', 'high', 'critical'
    source: str = 'unknown'
    description: str = ''
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: Optional[datetime] = None
    
    def to_dict(self) -> Dict:
        return {
            'type': self.type,
            'value': self.value,
            'severity': self.severity,
            'source': self.source,
            'description': self.description,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat() if self.last_seen else None
        }


class ThreatIntelligence:
    """Manages threat intelligence feeds and indicators."""
    
    def __init__(self, sources: Optional[List[Dict]] = None, config: Optional[Dict] = None):
        """
        Initialize threat intelligence engine.

        Args:
            sources: Explicit list of threat source dicts.
            config: Config dict; threat_sources extracted if sources not given.
        """
        self.sources: List[ThreatSource] = []
        self.indicators: Dict[str, ThreatIndicator] = {}
        resolved_sources = sources
        if resolved_sources is None and config:
            resolved_sources = config.get('threat_sources', None)
        self._load_sources(resolved_sources or self._default_sources())
    
    def _default_sources(self) -> List[Dict]:
        return [
            {
                'name': 'Moltbook',
                'url': 'https://www.moltbook.com/security-feed.json',
                'enabled': True,
                'priority': 1
            },
            {
                'name': 'Community',
                'url': 'https://api.sksecurity.com/threats',
                'enabled': True,
                'priority': 2
            }
        ]
    
    def _load_sources(self, sources: List[Dict]):
        """Load threat sources from configuration."""
        for src in sources:
            self.sources.append(ThreatSource(
                name=src.get('name', 'unknown'),
                url=src.get('url', ''),
                enabled=src.get('enabled', True),
                priority=src.get('priority', 1)
            ))
    
    def update(self) -> int:
        """Update threat intelligence from all sources."""
        new_indicators = 0
        for source in self.sources:
            threats = source.fetch()
            for threat in threats:
                indicator = self._parse_threat(threat, source.name)
                if indicator.value not in self.indicators:
                    self.indicators[indicator.value] = indicator
                    new_indicators += 1
        return new_indicators
    
    def _parse_threat(self, threat: Dict, source_name: str) -> ThreatIndicator:
        """Parse a threat dict into a ThreatIndicator."""
        return ThreatIndicator(
            type=threat.get('type', 'unknown'),
            value=threat.get('value', ''),
            severity=threat.get('severity', 'medium'),
            source=source_name,
            description=threat.get('description', ''),
            first_seen=datetime.now()
        )
    
    def check(self, value: str) -> Optional[ThreatIndicator]:
        """Check if a value is a known threat."""
        return self.indicators.get(value)
    
    def is_threat(self, value: str) -> bool:
        """Quick check if value is a known threat."""
        return value in self.indicators
    
    def get_threats(self, severity: Optional[str] = None) -> List[ThreatIndicator]:
        """Get all threats, optionally filtered by severity."""
        threats = list(self.indicators.values())
        if severity:
            threats = [t for t in threats if t.severity == severity]
        return threats
    
    def add_custom_threat(self, indicator: ThreatIndicator):
        """Add a custom threat indicator."""
        self.indicators[indicator.value] = indicator
    
    def get_patterns(self) -> List[Dict[str, Any]]:
        """
        Return regex-based threat patterns for the scanner engine.

        Returns:
            List of pattern dicts with keys: pattern, type, severity,
            confidence, source.
        """
        return self._builtin_patterns() + self._indicators_as_patterns()

    def _indicators_as_patterns(self) -> List[Dict[str, Any]]:
        """Convert loaded indicators into scanner-compatible patterns."""
        patterns: List[Dict[str, Any]] = []
        for indicator in self.indicators.values():
            if indicator.type == 'signature' and indicator.value:
                patterns.append({
                    'pattern': indicator.value,
                    'type': indicator.type,
                    'severity': indicator.severity.upper(),
                    'confidence': 0.85,
                    'source': indicator.source,
                })
        return patterns

    @staticmethod
    def _builtin_patterns() -> List[Dict[str, Any]]:
        """Built-in threat detection patterns that ship with sksecurity."""
        return [
            {
                'pattern': r'(?:exec|eval)\s*\(',
                'type': 'code_injection',
                'severity': 'CRITICAL',
                'confidence': 0.9,
                'source': 'builtin',
            },
            {
                'pattern': r'subprocess\.(?:call|run|Popen|check_output)\s*\(',
                'type': 'command_injection',
                'severity': 'HIGH',
                'confidence': 0.85,
                'source': 'builtin',
            },
            {
                'pattern': r'os\.system\s*\(',
                'type': 'command_injection',
                'severity': 'HIGH',
                'confidence': 0.9,
                'source': 'builtin',
            },
            {
                'pattern': r'(?:password|passwd|secret|api_key|apikey|token)\s*=\s*["\'][^"\']{8,}["\']',
                'type': 'hardcoded_secrets',
                'severity': 'CRITICAL',
                'confidence': 0.8,
                'source': 'builtin',
            },
            {
                'pattern': r'(?:AKIA|ASIA)[A-Z0-9]{16}',
                'type': 'hardcoded_secrets',
                'severity': 'CRITICAL',
                'confidence': 0.95,
                'source': 'builtin',
            },
            {
                'pattern': r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----',
                'type': 'hardcoded_secrets',
                'severity': 'CRITICAL',
                'confidence': 0.99,
                'source': 'builtin',
            },
            {
                'pattern': r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}',
                'type': 'hardcoded_secrets',
                'severity': 'CRITICAL',
                'confidence': 0.95,
                'source': 'builtin',
            },
            {
                'pattern': r'npm_[A-Za-z0-9]{36,}',
                'type': 'hardcoded_secrets',
                'severity': 'CRITICAL',
                'confidence': 0.95,
                'source': 'builtin',
            },
            {
                'pattern': r'(?:curl|wget)\s+.*\|\s*(?:bash|sh|zsh)',
                'type': 'remote_code_execution',
                'severity': 'HIGH',
                'confidence': 0.85,
                'source': 'builtin',
            },
            {
                'pattern': r'__import__\s*\(',
                'type': 'code_injection',
                'severity': 'HIGH',
                'confidence': 0.8,
                'source': 'builtin',
            },
            {
                'pattern': r'pickle\.loads?\s*\(',
                'type': 'deserialization',
                'severity': 'HIGH',
                'confidence': 0.85,
                'source': 'builtin',
            },
            {
                'pattern': r'yaml\.(?:load|unsafe_load)\s*\(',
                'type': 'deserialization',
                'severity': 'MEDIUM',
                'confidence': 0.7,
                'source': 'builtin',
            },
        ]

    def get_status(self) -> Dict[str, Any]:
        """
        Return current threat intelligence status.

        Returns:
            Dict with total_patterns, last_update, sources list.
        """
        last_updates = [
            s.last_fetch for s in self.sources if s.last_fetch is not None
        ]
        return {
            'total_patterns': len(self.get_patterns()),
            'last_update': max(last_updates).isoformat() if last_updates else 'never',
            'sources': [
                {'name': s.name, 'enabled': s.enabled, 'last_fetch': s.last_fetch.isoformat() if s.last_fetch else None}
                for s in self.sources
            ],
        }

    def export(self, filepath: str):
        """Export threat intelligence to JSON file."""
        data = {
            'updated': datetime.now().isoformat(),
            'sources': [s.name for s in self.sources],
            'indicators': {k: v.to_dict() for k, v in self.indicators.items()}
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
