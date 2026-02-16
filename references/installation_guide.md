# SKSecurity Enterprise Installation Guide

## Quick Installation

### One-Command Installation
```bash
# Download and install (when publicly available)
curl -sSL https://raw.githubusercontent.com/smilinTux/SKSecurity/main/install.sh | bash

# Or from OpenClaw skill:
python3 scripts/install_security.py
```

## Manual Installation

### 1. Prerequisites
```bash
# Ensure Python 3.8+ is installed
python3 --version

# Ensure SQLite3 is available
sqlite3 --version

# Check systemd availability (optional)
systemctl --version
```

### 2. Framework Detection
The installer automatically detects:
- **OpenClaw**: Looks for `~/.openclaw/openclaw.json`
- **AutoGPT**: Checks for `autogpt/` directory
- **LangChain**: Checks for `langchain/` directory
- **Generic**: Falls back to universal installation

### 3. Installation Process
1. **Directory Structure**: Creates `security/` directory with subdirectories
2. **Security Scripts**: Installs core security engine and tools
3. **Database**: Initializes SQLite security database
4. **Configuration**: Creates security policies and settings
5. **Automation**: Sets up daily security audit cron/systemd timer
6. **Dashboard**: Installs web-based security operations center

### 4. Post-Installation
```bash
# Verify installation
ls -la security/

# Check database initialization
sqlite3 security/security.db ".tables"

# Test security scanner
python3 security/scripts/advanced_security_system.py update-intel

# Launch dashboard
python3 security/launch_dashboard.py
```

## Configuration

### Security Policies (`security/config/security.json`)
```json
{
  "security": {
    "enabled": true,
    "auto_quarantine": true,
    "risk_threshold": 80,
    "dashboard_port": 8888,
    "threat_sources": [
      {"name": "Moltbook", "enabled": true},
      {"name": "NVD", "enabled": true}, 
      {"name": "GitHub", "enabled": true}
    ]
  }
}
```

### Automation Setup
- **systemd**: Creates user timer for daily audits
- **fallback**: Manual cron job setup if systemd unavailable
- **schedule**: Daily security audit at 6:00 AM local time

## Troubleshooting

### Common Issues
1. **Permission errors**: Ensure user has write access to installation directory
2. **SQLite missing**: Install sqlite3 package for your distribution
3. **systemd unavailable**: Manual cron setup required
4. **Port conflicts**: Change dashboard_port in configuration

### Verification Commands
```bash
# Check security database
python3 -c "import sqlite3; print('SQLite OK')"

# Test threat intelligence update
python3 security/scripts/update_threats.py

# Verify web dashboard
curl -s http://localhost:8888/api/status
```

## Support

### Community Support
- **GitHub Issues**: Report bugs and feature requests
- **Moltbook Community**: AI agent security discussions
- **Discord**: Real-time community help

### Enterprise Support
- **Professional Installation**: Custom deployment assistance
- **Integration Support**: Framework-specific customizations
- **24/7 Support**: Enterprise SLA guarantees