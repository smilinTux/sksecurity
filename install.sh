#!/bin/bash
# SKSecurity Enterprise Universal Installer
# Works with any AI framework: OpenClaw, AutoGPT, LangChain, custom
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SKSECURITY_VERSION="1.0.0"
INSTALL_DIR="$HOME/.sksecurity"
BIN_DIR="$HOME/.local/bin"
CONFIG_DIR="$HOME/.config/sksecurity"
REPO_URL="https://github.com/smilinTux/SKSecurity"
RAW_URL="https://raw.githubusercontent.com/smilinTux/SKSecurity/main"

# Banner
print_banner() {
    echo -e "${BLUE}"
    echo "🛡️  SKSecurity Enterprise Installer"
    echo "======================================"
    echo -e "${NC}"
    echo -e "${CYAN}Enterprise-grade AI agent security${NC}"
    echo -e "${PURPLE}Version: $SKSECURITY_VERSION${NC}"
    echo ""
}

# Logging
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check requirements
check_requirements() {
    log_info "Checking system requirements..."
    
    # Check OS
    if [[ "$OSTYPE" != "linux-gnu"* ]] && [[ "$OSTYPE" != "darwin"* ]]; then
        log_error "Unsupported operating system: $OSTYPE"
        log_info "SKSecurity supports Linux and macOS"
        exit 1
    fi
    
    # Check Python
    if command -v python3 &> /dev/null; then
        PYTHON="python3"
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        log_success "Python found: $PYTHON_VERSION"
    elif command -v python &> /dev/null; then
        PYTHON="python"
        PYTHON_VERSION=$(python --version | cut -d' ' -f2)
        log_warn "Using python instead of python3: $PYTHON_VERSION"
    else
        log_error "Python not found"
        log_info "Please install Python 3.8+ and try again"
        exit 1
    fi
    
    # Check Python version
    PYTHON_MAJOR_VERSION=$(echo $PYTHON_VERSION | cut -d'.' -f1)
    PYTHON_MINOR_VERSION=$(echo $PYTHON_VERSION | cut -d'.' -f2)
    
    if [ "$PYTHON_MAJOR_VERSION" -lt 3 ] || [ "$PYTHON_MINOR_VERSION" -lt 8 ]; then
        log_error "Python 3.8+ required, found $PYTHON_VERSION"
        exit 1
    fi
    
    # Check pip
    if ! $PYTHON -m pip --version &> /dev/null; then
        log_error "pip not found"
        log_info "Please install pip for Python and try again"
        exit 1
    fi
    
    # Check curl or wget
    if command -v curl &> /dev/null; then
        DOWNLOADER="curl -fsSL"
    elif command -v wget &> /dev/null; then
        DOWNLOADER="wget -qO-"
    else
        log_error "curl or wget required for installation"
        exit 1
    fi
    
    log_success "System requirements satisfied"
}

# Detect AI framework
detect_framework() {
    log_info "Detecting AI framework environment..."
    
    FRAMEWORK="generic"
    
    # Check for OpenClaw
    if [ -f "$HOME/.openclaw/openclaw.json" ] || [ -f "openclaw.json" ] || command -v openclaw &> /dev/null; then
        FRAMEWORK="openclaw"
        log_success "OpenClaw framework detected"
        return
    fi
    
    # Check for AutoGPT
    if [ -d "autogpt" ] || [ -d "../autogpt" ] || [ -f "requirements.txt" ] && grep -q "autogpt" requirements.txt 2>/dev/null; then
        FRAMEWORK="autogpt"
        log_success "AutoGPT framework detected"
        return
    fi
    
    # Check for LangChain
    if [ -d "langchain" ] || [ -f "requirements.txt" ] && grep -q "langchain" requirements.txt 2>/dev/null; then
        FRAMEWORK="langchain"
        log_success "LangChain framework detected"
        return
    fi
    
    # Check for other common AI frameworks
    if [ -f "requirements.txt" ]; then
        if grep -E "(openai|anthropic|huggingface)" requirements.txt &> /dev/null; then
            FRAMEWORK="ai_project"
            log_info "AI project detected (generic installation)"
            return
        fi
    fi
    
    log_warn "No specific AI framework detected"
    log_info "Using generic installation mode"
}

# Create directories
create_directories() {
    log_info "Creating installation directories..."
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$BIN_DIR"  
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$INSTALL_DIR/logs"
    mkdir -p "$INSTALL_DIR/quarantine"
    
    # Add ~/.local/bin to PATH if not already there
    if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
        echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$HOME/.bashrc"
        echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$HOME/.profile"
        if [ -f "$HOME/.zshrc" ]; then
            echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$HOME/.zshrc"
        fi
        log_info "Added $BIN_DIR to PATH (restart shell or source ~/.bashrc)"
    fi
    
    log_success "Directories created"
}

# Download and install SKSecurity
install_sksecurity() {
    log_info "Downloading SKSecurity package..."
    
    # Create temporary directory
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    # Download latest release
    if ! $DOWNLOADER "$RAW_URL/sksecurity.tar.gz" -o sksecurity.tar.gz 2>/dev/null; then
        # Fallback: create a minimal package from components
        log_warn "Release package not available, installing from components..."
        
        # Download core components
        mkdir -p sksecurity
        $DOWNLOADER "$RAW_URL/sksecurity/__init__.py" -o sksecurity/__init__.py
        $DOWNLOADER "$RAW_URL/sksecurity/cli.py" -o sksecurity/cli.py
        $DOWNLOADER "$RAW_URL/sksecurity/scanner.py" -o sksecurity/scanner.py
        $DOWNLOADER "$RAW_URL/sksecurity/dashboard.py" -o sksecurity/dashboard.py
        $DOWNLOADER "$RAW_URL/requirements.txt" -o requirements.txt
        
        # Create minimal setup
        cat > setup.py << EOF
from setuptools import setup, find_packages

setup(
    name="sksecurity",
    version="$SKSECURITY_VERSION",
    packages=find_packages(),
    install_requires=[
        "click>=8.0",
        "requests>=2.25",
        "sqlite3",
    ],
    entry_points={
        'console_scripts': [
            'sksecurity=sksecurity.cli:main',
        ],
    },
)
EOF
    else
        tar -xzf sksecurity.tar.gz
    fi
    
    # Install package
    log_info "Installing SKSecurity package..."
    $PYTHON -m pip install --user . --upgrade
    
    # Create sksecurity command if not available
    if ! command -v sksecurity &> /dev/null; then
        log_info "Creating sksecurity command..."
        cat > "$BIN_DIR/sksecurity" << EOF
#!/bin/bash
exec $PYTHON -m sksecurity.cli "\$@"
EOF
        chmod +x "$BIN_DIR/sksecurity"
    fi
    
    # Cleanup
    cd - > /dev/null
    rm -rf "$TEMP_DIR"
    
    log_success "SKSecurity installed successfully"
}

# Create default configuration  
create_config() {
    log_info "Creating default configuration..."
    
    cat > "$CONFIG_DIR/config.yml" << EOF
# SKSecurity Enterprise Configuration
security:
  enabled: true
  auto_quarantine: true
  risk_threshold: 80
  dashboard_port: 8888
  framework: "$FRAMEWORK"
  
threat_sources:
  - name: "Moltbook"
    url: "https://www.moltbook.com/security-feed.json"
    enabled: true
    priority: 1
  - name: "Community"
    url: "https://api.sksecurity.com/threats"
    enabled: true
    priority: 2

monitoring:
  runtime_monitoring: true
  file_system_monitoring: true
  network_monitoring: false
  
notifications:
  critical_alerts: true
  daily_reports: false
  webhook_url: null

paths:
  install_dir: "$INSTALL_DIR"
  quarantine_dir: "$INSTALL_DIR/quarantine"
  logs_dir: "$INSTALL_DIR/logs"
EOF
    
    log_success "Configuration created at $CONFIG_DIR/config.yml"
}

# Run initial setup
initial_setup() {
    log_info "Running initial setup..."
    
    # Initialize security database
    if command -v sksecurity &> /dev/null || [ -x "$BIN_DIR/sksecurity" ]; then
        export PATH="$BIN_DIR:$PATH"
        
        log_info "Initializing security database..."
        sksecurity init --framework "$FRAMEWORK" || log_warn "Database initialization incomplete (will retry later)"
        
        log_info "Updating threat intelligence..."
        sksecurity update || log_warn "Threat intelligence update incomplete (will retry later)"
        
        log_success "Initial setup completed"
    else
        log_warn "sksecurity command not available yet, skipping initial setup"
    fi
}

# Print success message
print_success() {
    echo ""
    echo -e "${GREEN}🎉 SKSecurity Enterprise Installation Complete!${NC}"
    echo -e "${BLUE}=============================================${NC}"
    echo ""
    echo -e "${CYAN}🛡️ Your AI agents are now protected by enterprise-grade security!${NC}"
    echo ""
    echo -e "${YELLOW}📍 Quick Start Commands:${NC}"
    echo -e "   ${PURPLE}sksecurity --help${NC}                 # Show all commands"
    echo -e "   ${PURPLE}sksecurity scan ./my-agent${NC}        # Scan an AI agent"
    echo -e "   ${PURPLE}sksecurity dashboard${NC}              # Launch security dashboard"
    echo -e "   ${PURPLE}sksecurity monitor --continuous${NC}   # Start continuous monitoring"
    echo ""
    echo -e "${YELLOW}📊 Security Dashboard:${NC}"
    echo -e "   Run: ${PURPLE}sksecurity dashboard${NC}"
    echo -e "   Visit: ${CYAN}http://localhost:8888${NC}"
    echo ""
    echo -e "${YELLOW}📁 Configuration:${NC}"
    echo -e "   Config: ${PURPLE}$CONFIG_DIR/config.yml${NC}"
    echo -e "   Logs: ${PURPLE}$INSTALL_DIR/logs/${NC}"
    echo -e "   Quarantine: ${PURPLE}$INSTALL_DIR/quarantine/${NC}"
    echo ""
    echo -e "${YELLOW}🌐 Community & Support:${NC}"
    echo -e "   GitHub: ${CYAN}https://github.com/smilinTux/SKSecurity${NC}"
    echo -e "   Support: ${CYAN}support@smilintux.org${NC}"
    echo -e "   Discord: ${CYAN}https://discord.gg/sksecurity${NC}"
    echo -e "   Enterprise: ${CYAN}sales@smilintux.org${NC}"
    echo ""
    if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
        echo -e "${YELLOW}⚠️  Please restart your shell or run:${NC}"
        echo -e "   ${PURPLE}source ~/.bashrc${NC}"
        echo ""
    fi
    echo -e "${GREEN}✨ Welcome to enterprise-grade AI security!${NC}"
}

# Handle errors
handle_error() {
    echo ""
    log_error "Installation failed!"
    echo ""
    echo -e "${YELLOW}Troubleshooting:${NC}"
    echo "1. Ensure Python 3.8+ is installed"
    echo "2. Ensure pip is available"  
    echo "3. Check internet connectivity"
    echo "4. Try running with sudo if permission issues"
    echo ""
    echo -e "${CYAN}For support:${NC}"
    echo "• GitHub: https://github.com/smilinTux/SKSecurity/issues"
    echo "• Discord: https://discord.gg/sksecurity"
    echo "• Email: support@smilintux.org"
    exit 1
}

# Main installation function
main() {
    print_banner
    
    # Set up error handling
    trap handle_error ERR
    
    # Run installation steps
    check_requirements
    detect_framework
    create_directories
    install_sksecurity
    create_config
    initial_setup
    print_success
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --framework)
            FRAMEWORK="$2"
            shift 2
            ;;
        --version)
            echo "SKSecurity Enterprise Installer v$SKSECURITY_VERSION"
            exit 0
            ;;
        --help)
            echo "SKSecurity Enterprise Installer"
            echo ""
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --framework FRAMEWORK    Force specific framework (openclaw, autogpt, langchain, generic)"
            echo "  --version               Show version"
            echo "  --help                  Show this help"
            echo ""
            echo "Examples:"
            echo "  $0                                    # Auto-detect framework"
            echo "  $0 --framework openclaw              # Force OpenClaw installation"  
            echo "  $0 --framework generic               # Generic installation"
            echo ""
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Run main installation
main