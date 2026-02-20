"""SKSecurity Enterprise - Security Configuration Module"""
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import json
import yaml


@dataclass
class SecurityPolicy:
    """Represents a security policy rule."""
    name: str
    enabled: bool = True
    severity_threshold: str = 'medium'
    auto_quarantine: bool = False
    scan_depth: int = 3
    file_extensions: List[str] = field(default_factory=lambda: ['.py', '.js', '.ts', '.sh', '.md'])
    excluded_paths: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'enabled': self.enabled,
            'severity_threshold': self.severity_threshold,
            'auto_quarantine': self.auto_quarantine,
            'scan_depth': self.scan_depth,
            'file_extensions': self.file_extensions,
            'excluded_paths': self.excluded_paths
        }


class SecurityConfig:
    """Manages security configuration and policies."""
    
    DEFAULT_CONFIG = {
        'security': {
            'enabled': True,
            'auto_quarantine': False,
            'risk_threshold': 80,
            'dashboard_port': 8888,
            'log_level': 'INFO'
        },
        'scanning': {
            'default_depth': 3,
            'parallel_scans': 4,
            'timeout_seconds': 300,
            'extensions': ['.py', '.js', '.ts', '.sh', '.md', '.json', '.yml', '.yaml']
        },
        'monitoring': {
            'runtime_monitoring': True,
            'file_system_monitoring': True,
            'network_monitoring': False,
            'check_interval': 60
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
        'policies': []
    }
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or str(Path.home() / '.sksecurity' / 'config.yaml')
        self._config = self._load_config()
        self._policies: Dict[str, SecurityPolicy] = {}
        self._load_policies()
    
    def _load_config(self) -> Dict:
        """Load configuration from file or use defaults."""
        if Path(self.config_path).exists():
            try:
                with open(self.config_path, 'r') as f:
                    if self.config_path.endswith('.yaml') or self.config_path.endswith('.yml'):
                        return yaml.safe_load(f) or self.DEFAULT_CONFIG.copy()
                    else:
                        return json.load(f) or self.DEFAULT_CONFIG.copy()
            except Exception:
                pass
        return self.DEFAULT_CONFIG.copy()
    
    def _load_policies(self):
        """Load security policies from config."""
        policy_data = self._config.get('policies', [])
        for p in policy_data:
            policy = SecurityPolicy(
                name=p.get('name', 'default'),
                enabled=p.get('enabled', True),
                severity_threshold=p.get('severity_threshold', 'medium'),
                auto_quarantine=p.get('auto_quarantine', False),
                scan_depth=p.get('scan_depth', 3),
                file_extensions=p.get('file_extensions', ['.py', '.js']),
                excluded_paths=p.get('excluded_paths', [])
            )
            self._policies[policy.name] = policy
    
    def save(self):
        """Save current configuration to file."""
        Path(self.config_path).parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(self.config_path, 'w') as f:
                yaml.dump(self._config, f, default_flow_style=False)
        except Exception as e:
            print(f"Error saving config: {e}")
    
    # Security settings
    @property
    def enabled(self) -> bool:
        return self._config.get('security', {}).get('enabled', True)
    
    @enabled.setter
    def enabled(self, value: bool):
        self._config.setdefault('security', {})['enabled'] = value
        self.save()
    
    @property
    def auto_quarantine(self) -> bool:
        return self._config.get('security', {}).get('auto_quarantine', False)
    
    @property
    def risk_threshold(self) -> int:
        return self._config.get('security', {}).get('risk_threshold', 80)
    
    @property
    def dashboard_port(self) -> int:
        return self._config.get('security', {}).get('dashboard_port', 8888)
    
    # Scanning settings
    @property
    def default_depth(self) -> int:
        return self._config.get('scanning', {}).get('default_depth', 3)
    
    @property
    def extensions(self) -> List[str]:
        return self._config.get('scanning', {}).get('extensions', [])
    
    # Monitoring settings
    @property
    def runtime_monitoring(self) -> bool:
        return self._config.get('monitoring', {}).get('runtime_monitoring', True)
    
    @property
    def file_system_monitoring(self) -> bool:
        return self._config.get('monitoring', {}).get('file_system_monitoring', True)
    
    # Policies
    def get_policy(self, name: str) -> Optional[SecurityPolicy]:
        return self._policies.get(name)
    
    def add_policy(self, policy: SecurityPolicy):
        self._policies[policy.name] = policy
        if 'policies' not in self._config:
            self._config['policies'] = []
        self._config['policies'].append(policy.to_dict())
        self.save()
    
    def remove_policy(self, name: str) -> bool:
        if name in self._policies:
            del self._policies[name]
            self._config['policies'] = [p for p in self._config.get('policies', []) if p['name'] != name]
            self.save()
            return True
        return False
    
    def list_policies(self) -> List[SecurityPolicy]:
        return list(self._policies.values())
    
    # Threat sources
    def get_threat_sources(self) -> List[Dict]:
        return self._config.get('threat_sources', [])
    
    def add_threat_source(self, source: Dict):
        if 'threat_sources' not in self._config:
            self._config['threat_sources'] = []
        self._config['threat_sources'].append(source)
        self.save()
    
    # Utility
    def get(self, key: str, default: Any = None) -> Any:
        """Get a config value using dot notation."""
        keys = key.split('.')
        value = self._config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
        return value if value is not None else default
    
    def set(self, key: str, value: Any):
        """Set a config value using dot notation."""
        keys = key.split('.')
        config = self._config
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        config[keys[-1]] = value
        self.save()
    
    def to_dict(self) -> Dict:
        return self._config.copy()
