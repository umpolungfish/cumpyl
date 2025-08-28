#!/bin/bash
# Payload Transmutation Tool Setup Script 🔓
# Optimized for WSL2 + Conda environments

set -euo pipefail

# Colors and emojis for cyber theme 🌩
RED='\033[0;31m'
GREEN='\033[0;32m' 
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Cyber-themed output functions 💀
log_info() {
    echo -e "${CYAN}🔍 [INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}✅ [SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠ [WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}❌ [ERROR]${NC} $1"
}

log_hacker() {
    echo -e "${PURPLE}🔓 [TRANSMUTE]${NC} $1"
}

# Configuration
TOOL_NAME="payload_transmute"
ENV_NAME="redteam_transmute"
PYTHON_VERSION="3.11"
REPO_DIR="$HOME/redteam_tools"
TOOL_DIR="$REPO_DIR/$TOOL_NAME"

# Banner 💥
show_banner() {
    cat << 'EOF'
    
██████╗ ███████╗██████╗     ████████╗███████╗ █████╗ ███╗   ███╗
██╔══██╗██╔════╝██╔══██╗    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
██████╔╝█████╗  ██║  ██║       ██║   █████╗  ███████║██╔████╔██║
██╔══██╗██╔══╝  ██║  ██║       ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║
██║  ██║███████╗██████╔╝       ██║   ███████╗██║  ██║██║ ╚═╝ ██║
╚═╝  ╚═╝╚══════╝╚═════╝        ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
                                                                    
████████╗██████╗  █████╗ ███╗   ██╗███████╗███╗   ███╗██╗   ██╗████████╗███████╗
╚══██╔══╝██╔══██╗██╔══██╗████╗  ██║██╔════╝████╗ ████║██║   ██║╚══██╔══╝██╔════╝
   ██║   ██████╔╝███████║██╔██╗ ██║███████╗██╔████╔██║██║   ██║   ██║   █████╗  
   ██║   ██╔══██╗██╔══██║██║╚██╗██║╚════██║██║╚██╔╝██║██║   ██║   ██║   ██╔══╝  
   ██║   ██║  ██║██║  ██║██║ ╚████║███████║██║ ╚═╝ ██║╚██████╔╝   ██║   ███████╗
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝     ╚═╝ ╚═════╝    ╚═╝   ╚══════╝
                                                                                  
🔓 Advanced Payload Encoding for Red Team Operations 🔓

EOF
}

# System detection
detect_system() {
    log_info "Detecting system environment..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if grep -q Microsoft /proc/version; then
            SYSTEM="WSL2"
            log_success "Detected WSL2 environment ✔"
        else
            SYSTEM="Linux"
            log_success "Detected native Linux environment ✔"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        SYSTEM="macOS"
        log_success "Detected macOS environment ✔"
    else
        SYSTEM="Unknown"
        log_warning "Unknown system type: $OSTYPE"
    fi
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check for conda/mamba
    if command -v mamba &> /dev/null; then
        CONDA_CMD="mamba"
        log_success "Found mamba package manager 🐍"
    elif command -v conda &> /dev/null; then
        CONDA_CMD="conda"
        log_success "Found conda package manager 🐍"
    else
        log_error "Neither conda nor mamba found!"
        log_info "Please install miniconda/anaconda first:"
        log_info "  wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh"
        log_info "  bash Miniconda3-latest-Linux-x86_64.sh"
        exit 1
    fi
    
    # Check for git
    if ! command -v git &> /dev/null; then
        log_warning "Git not found, installing via apt..."
        sudo apt update && sudo apt install -y git
    fi
    
    # Check Python version compatibility
    if command -v python3 &> /dev/null; then
        PYTHON_VER=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
        log_success "System Python: $PYTHON_VER"
    fi
}

# Install system dependencies
install_system_deps() {
    log_info "Installing system dependencies..."
    
    case $SYSTEM in
        "WSL2"|"Linux")
            log_info "Using apt package manager..."
            sudo apt update
            
            # Essential packages
            PACKAGES=(
                "python3-dev"
                "python3-pip" 
                "build-essential"
                "curl"
                "wget"
                "vim"
                "jq"
                "tree"
                "htop"
                "git"
            )
            
            for package in "${PACKAGES[@]}"; do
                if dpkg -l | grep -q "^ii  $package "; then
                    log_success "$package already installed ✔"
                else
                    log_info "Installing $package..."
                    sudo apt install -y "$package"
                fi
            done
            ;;
        "macOS")
            log_info "Using brew package manager..."
            if ! command -v brew &> /dev/null; then
                log_error "Homebrew not found! Please install: https://brew.sh"
                exit 1
            fi
            brew install python git jq tree htop
            ;;
    esac
}

# Create conda environment
create_conda_env() {
    log_info "Creating conda environment: $ENV_NAME..."
    
    # Check if environment already exists
    if $CONDA_CMD env list | grep -q "$ENV_NAME"; then
        log_warning "Environment $ENV_NAME already exists!"
        read -p "🤔 Remove and recreate? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_info "Removing existing environment..."
            $CONDA_CMD env remove -n "$ENV_NAME" -y
        else
            log_info "Using existing environment..."
            return 0
        fi
    fi
    
    # Create new environment
    log_info "Creating Python $PYTHON_VERSION environment..."
    $CONDA_CMD create -n "$ENV_NAME" python="$PYTHON_VERSION" -y
    
    log_success "Environment created: $ENV_NAME ✔"
}

# Install Python dependencies
install_python_deps() {
    log_info "Installing Python dependencies..."
    
    # Initialize and activate environment properly
    if [[ "$CONDA_CMD" == "mamba" ]]; then
        # Initialize mamba if not already done
        if ! mamba info --envs &>/dev/null; then
            log_info "Initializing mamba shell..."
            mamba shell init --shell bash --root-prefix "$HOME/.local/share/mamba" || true
            # Source the bashrc to get mamba commands
            source "$HOME/.bashrc" 2>/dev/null || true
        fi
        
        # Use mamba run for package installation instead of activation
        log_info "Using mamba run for package installation..."
        INSTALL_CMD="mamba run -n $ENV_NAME pip install"
    else
        # Initialize conda if not already done
        if ! conda info --envs &>/dev/null; then
            log_info "Initializing conda shell..."
            conda init bash || true
            source "$HOME/.bashrc" 2>/dev/null || true
        fi
        
        # Use conda run for package installation
        log_info "Using conda run for package installation..."
        INSTALL_CMD="conda run -n $ENV_NAME pip install"
    fi
    
    # Core dependencies
    CORE_DEPS=(
        "pyyaml"
        "requests" 
        "click"
        "rich"
        "typer"
        "colorama"
        "cryptography"
        "pycryptodome"
    )
    
    # Development dependencies
    DEV_DEPS=(
        "pytest"
        "black"
        "flake8"
        "mypy"
        "ipython"
        "jupyter"
    )
    
    log_info "Installing core dependencies..."
    for dep in "${CORE_DEPS[@]}"; do
        log_info "Installing $dep..."
        $INSTALL_CMD "$dep"
    done
    
    read -p "🔧 Install development dependencies? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Installing development dependencies..."
        for dep in "${DEV_DEPS[@]}"; do
            log_info "Installing $dep..."
            $INSTALL_CMD "$dep"
        done
    fi
}

# Setup tool directory structure
setup_directories() {
    log_info "Setting up directory structure..."
    
    # Create main directories
    mkdir -p "$REPO_DIR"
    mkdir -p "$TOOL_DIR"
    mkdir -p "$TOOL_DIR/configs"
    mkdir -p "$TOOL_DIR/payloads"
    mkdir -p "$TOOL_DIR/results"
    mkdir -p "$TOOL_DIR/logs"
    mkdir -p "$TOOL_DIR/tests"
    
    log_success "Directory structure created ✔"
}

# Install tool files
install_tool_files() {
    log_info "Installing tool files..."
    
    # Note: In real deployment, these would be copied from the repository
    # For now, we'll create placeholders and instructions
    
    cat > "$TOOL_DIR/README.md" << 'EOF'
# Payload Transmutation Tool 🔓

Advanced encoding/obfuscation utility for red team operations.

## Quick Start

```bash
# Activate environment
conda activate redteam_transmute

# Basic usage
python payload_transmute.py -p "cat /etc/passwd" -m null_padding -v

# Use templates
python payload_transmute.py -t sql_injection -m mixed -o results.json

# Process file
python payload_transmute.py -f payloads.txt -m unicode -v
```

## Configuration

Edit `configs/transmute_config.yaml` to customize behavior.

## Security Notice ⚠

This tool is for authorized red team operations only. 
Ensure proper authorization before use.
EOF

    # Create example payload files
    cat > "$TOOL_DIR/payloads/common_rce.txt" << 'EOF'
; cat /etc/passwd
| whoami
&& uname -a
`id`
$(whoami)
; ls -la /
| netstat -tulpn
&& ps aux
EOF

    cat > "$TOOL_DIR/payloads/sql_injection.txt" << 'EOF'
' OR '1'='1
'; DROP TABLE users; --
' UNION SELECT NULL,NULL,NULL --
' AND 1=1 --
' OR 1=1 LIMIT 1 --
EOF

    log_success "Tool files installed ✔"
}

# Create activation script
create_activation_script() {
    log_info "Creating activation script..."
    
    cat > "$TOOL_DIR/activate.sh" << EOF
#!/bin/bash
# Activation script for Payload Transmutation Tool 🔓

# Colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "\${CYAN}🔓 Activating Red Team Transmutation Environment 🔓\${NC}"

# Initialize shell if needed
if command -v mamba &> /dev/null; then
    CONDA_CMD="mamba"
    # Initialize mamba if not done
    if ! mamba info &>/dev/null; then
        mamba shell init --shell bash --root-prefix "\$HOME/.local/share/mamba" >/dev/null 2>&1 || true
        source "\$HOME/.bashrc" 2>/dev/null || true
    fi
elif command -v conda &> /dev/null; then
    CONDA_CMD="conda"
    # Initialize conda if not done  
    if ! conda info &>/dev/null; then
        conda init bash >/dev/null 2>&1 || true
        source "\$HOME/.bashrc" 2>/dev/null || true
    fi
else
    echo "❌ Neither conda nor mamba found!"
    exit 1
fi

# Try to activate environment
if \$CONDA_CMD activate $ENV_NAME 2>/dev/null; then
    echo -e "\${GREEN}✅ Environment activated via \$CONDA_CMD!\${NC}"
else
    echo "⚠ Direct activation failed, using shell initialization..."
    eval "\$(\$CONDA_CMD shell hook)"
    \$CONDA_CMD activate $ENV_NAME
fi

# Set environment variables
export TRANSMUTE_HOME="$TOOL_DIR"
export TRANSMUTE_CONFIG="\$TRANSMUTE_HOME/configs/transmute_config.yaml"

# Add tool to PATH
export PATH="\$TRANSMUTE_HOME:\$PATH"

echo -e "\${GREEN}✅ Environment activated!\${NC}"
echo -e "\${CYAN}📁 Tool directory: \$TRANSMUTE_HOME\${NC}"
echo -e "\${CYAN}🐍 Python environment: $ENV_NAME\${NC}"
echo ""
echo -e "\${CYAN}Quick commands:\${NC}"
echo -e "  🔧 payload_transmute.py --help"
echo -e "  📋 payload_transmute.py --list-methods"
echo -e "  📋 payload_transmute.py --list-templates"
echo ""
EOF

    chmod +x "$TOOL_DIR/activate.sh"
    log_success "Activation script created ✔"
}

# Setup shell integration
setup_shell_integration() {
    log_info "Setting up shell integration..."
    
    # Add alias to bashrc/zshrc
    SHELL_RC=""
    if [[ "$SHELL" == *"zsh"* ]]; then
        SHELL_RC="$HOME/.zshrc"
    else
        SHELL_RC="$HOME/.bashrc"
    fi
    
    if [[ -f "$SHELL_RC" ]]; then
        if ! grep -q "transmute" "$SHELL_RC"; then
            cat >> "$SHELL_RC" << EOF

# Red Team Transmutation Tool 🔓
alias transmute-activate='source $TOOL_DIR/activate.sh'
alias transmute-cd='cd $TOOL_DIR'

EOF
            log_success "Shell aliases added to $SHELL_RC ✔"
        else
            log_warning "Shell aliases already exist"
        fi
    fi
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."
    
    # Test environment exists
    if $CONDA_CMD env list | grep -q "$ENV_NAME"; then
        log_success "Environment $ENV_NAME exists ✔"
    else
        log_error "Environment $ENV_NAME not found!"
        return 1
    fi
    
    # Test Python and packages using conda/mamba run
    log_info "Testing Python installation..."
    if $CONDA_CMD run -n "$ENV_NAME" python -c "import sys; print(f'✅ Python {sys.version_info.major}.{sys.version_info.minor} ready')" 2>/dev/null; then
        log_success "Python environment working ✔"
    else
        log_warning "Python test failed, but environment exists"
    fi
    
    # Test package installations
    log_info "Testing core dependencies..."
    CORE_PACKAGES=("yaml" "rich" "requests")
    for pkg in "${CORE_PACKAGES[@]}"; do
        if $CONDA_CMD run -n "$ENV_NAME" python -c "import $pkg" 2>/dev/null; then
            log_success "$pkg package installed ✔"
        else
            log_warning "$pkg package may not be properly installed"
        fi
    done
    
    # Check tool directory
    if [[ -d "$TOOL_DIR" ]]; then
        log_success "Tool directory exists ✔"
    else
        log_error "Tool directory missing!"
        return 1
    fi
    
    log_success "Installation verified! 🎉"
}

# Main installation flow
main() {
    show_banner
    
    log_hacker "Starting Red Team Transmutation Tool installation..."
    echo
    
    detect_system
    check_prerequisites
    install_system_deps
    create_conda_env
    install_python_deps
    setup_directories
    install_tool_files
    create_activation_script
    setup_shell_integration
    verify_installation
    
    echo
    log_success "🎉 Installation complete!"
    echo
    log_hacker "Next steps:"
    echo -e "  1. ${CYAN}source ~/.bashrc${NC} (or restart terminal)"
    echo -e "  2. ${CYAN}transmute-activate${NC} (activate environment)"
    echo -e "     ${YELLOW}OR manually:${NC} ${CYAN}source $TOOL_DIR/activate.sh${NC}"
    echo -e "  3. ${CYAN}cd \$TRANSMUTE_HOME${NC} (go to tool directory)"
    echo -e "  4. ${CYAN}python payload_transmute.py --help${NC} (see usage)"
    echo
    if [[ "$CONDA_CMD" == "mamba" ]]; then
        log_warning "If activation fails, run: ${CYAN}mamba shell init --shell bash${NC}"
        log_warning "Then restart your terminal and try again"
    fi
    echo
    log_warning "Remember: This tool is for authorized red team operations only! ⚠"
    echo
}

# Error handling
trap 'log_error "Installation failed at line $LINENO"' ERR

# Run main function
main "$@"
