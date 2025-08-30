#!/bin/bash
# Activation script for Payload Transmutation Tool 🔓

# Colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}🔓 Activating Red Team Transmutation Environment 🔓${NC}"

# Initialize shell if needed
if command -v mamba &> /dev/null; then
    CONDA_CMD="mamba"
    # Initialize mamba if not done
    if ! mamba info &>/dev/null; then
        mamba shell init --shell bash --root-prefix "$HOME/.local/share/mamba" >/dev/null 2>&1 || true
        source "$HOME/.bashrc" 2>/dev/null || true
    fi
elif command -v conda &> /dev/null; then
    CONDA_CMD="conda"
    # Initialize conda if not done  
    if ! conda info &>/dev/null; then
        conda init bash >/dev/null 2>&1 || true
        source "$HOME/.bashrc" 2>/dev/null || true
    fi
else
    echo "❌ Neither conda nor mamba found!"
    exit 1
fi

# Try to activate environment
if $CONDA_CMD activate redteam_transmute 2>/dev/null; then
    echo -e "${GREEN}✅ Environment activated via $CONDA_CMD!${NC}"
else
    echo "⚠ Direct activation failed, using shell initialization..."
    eval "$($CONDA_CMD shell hook)"
    $CONDA_CMD activate redteam_transmute
fi

# Set environment variables
export TRANSMUTE_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export TRANSMUTE_CONFIG="$TRANSMUTE_HOME/configs/transmute_config.yaml"

# Add tool to PATH
export PATH="$TRANSMUTE_HOME:$PATH"

echo -e "${GREEN}✅ Environment activated!${NC}"
echo -e "${CYAN}📁 Tool directory: $TRANSMUTE_HOME${NC}"
echo -e "${CYAN}🐍 Python environment: redteam_transmute${NC}"
echo ""
echo -e "${CYAN}Quick commands:${NC}"
echo -e "  🔧 payload_transmute.py --help"
echo -e "  📋 payload_transmute.py --list-methods"
echo -e "  📋 payload_transmute.py --list-templates"
echo ""