"""
SKSecurity Enterprise - AI Agent Security Platform
The only security solution AI agents need.
"""

__version__ = "1.2.0"
__author__ = "smilinTux Team + Queen Ara + Neuresthetics"
__license__ = "Apache-2.0"
__description__ = "Enterprise-grade security for AI agent ecosystems"

from .scanner import SecurityScanner, ScanResult
from .intelligence import ThreatIntelligence, ThreatSource
from .dashboard import DashboardServer, SecurityDashboard
from .database import SecurityDatabase, SecurityEvent
from .config import SecurityConfig, SecurityPolicy
from .monitor import SecurityMonitor, RuntimeMonitor
from .quarantine import QuarantineManager, QuarantineRecord
from .email_screener import EmailScreener, ScreeningResult, Verdict, ThreatCategory
from .secret_guard import SecretGuard, GuardResult, SecretFinding
from .truth_engine import TruthEngine, TruthVerdict

# Main API exports
__all__ = [
    # Core scanning
    'SecurityScanner',
    'ScanResult',

    # Email & input screening
    'EmailScreener',
    'ScreeningResult',
    'Verdict',
    'ThreatCategory',

    # Secret leak prevention
    'SecretGuard',
    'GuardResult',
    'SecretFinding',

    # Threat intelligence
    'ThreatIntelligence',
    'ThreatSource',

    # Dashboard and monitoring
    'DashboardServer',
    'SecurityDashboard',
    'SecurityMonitor',
    'RuntimeMonitor',

    # Database and events
    'SecurityDatabase',
    'SecurityEvent',

    # Configuration
    'SecurityConfig',
    'SecurityPolicy',

    # Quarantine system
    'QuarantineManager',
    'QuarantineRecord',

    # Truth engine (Neuresthetics seed integration)
    'TruthEngine',
    'TruthVerdict',

    # Version info
    '__version__',
    '__author__',
    '__license__',
    '__description__',
]

# Default security configuration
DEFAULT_CONFIG = {
    'security': {
        'enabled': True,
        'auto_quarantine': True,
        'risk_threshold': 80,
        'dashboard_port': 8888,
    },
    'threat_sources': [
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
    ],
    'monitoring': {
        'runtime_monitoring': True,
        'file_system_monitoring': True,
        'network_monitoring': False,
    }
}

def get_version():
    """Get SKSecurity version string."""
    return __version__

def get_default_config():
    """Get default security configuration."""
    return DEFAULT_CONFIG.copy()

def create_scanner(**kwargs):
    """Create a SecurityScanner with default configuration."""
    return SecurityScanner(**kwargs)

def create_dashboard(**kwargs):
    """Create a SecurityDashboard with default configuration.""" 
    return SecurityDashboard(**kwargs)

def quick_scan(path, **kwargs):
    """Quick security scan of a path."""
    scanner = SecurityScanner(**kwargs)
    return scanner.scan(path)

# Banner for CLI
BANNER = """
🛡️  SKSecurity Enterprise
==========================
Enterprise-grade AI agent security
Version: {version}
""".format(version=__version__)