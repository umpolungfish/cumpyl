# ~/.bashrc: executed by bash(1) for non-login shells.
# SodaSuicide Framework Configuration
# Cyberpunk-themed autonomous research and fine-tuning framework

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

# =============================================================================
# BASIC BASH CONFIGURATION
# =============================================================================

# History configuration
HISTCONTROL=ignoreboth
shopt -s histappend
HISTSIZE=2000
HISTFILESIZE=4000

# Window size check
shopt -s checkwinsize

# Enable globstar pattern matching
shopt -s globstar

# Make lesspipe more friendly for non-text input files
[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

# Set variable identifying the chroot environment
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# =============================================================================
# CYBERPUNK PROMPT CONFIGURATION 
# =============================================================================

# Color definitions for cyberpunk theme
export NEON_GREEN='\033[38;5;46m'
export NEON_BLUE='\033[38;5;51m'
export NEON_PINK='\033[38;5;198m'
export NEON_ORANGE='\033[38;5;202m'
export NEON_PURPLE='\033[38;5;129m'
export CYBER_RED='\033[38;5;196m'
export DARK_GRAY='\033[38;5;240m'
export WHITE='\033[1;37m'
export NC='\033[0m' # No Color

# Cyberpunk prompt with SodaSuicide branding
case "$TERM" in
    xterm-color|*-256color) color_prompt=yes;;
esac

if [ "$color_prompt" = yes ]; then
    PS1='${debian_chroot:+($debian_chroot)}\[\033[38;5;46m\]┌─[\[\033[38;5;51m\]\u\[\033[38;5;240m\]@\[\033[38;5;198m\]\h\[\033[38;5;46m\]]\[\033[38;5;202m\]─[\[\033[38;5;129m\]\w\[\033[38;5;202m\]]\n\[\033[38;5;46m\]└─\[\033[38;5;196m\]▶\[\033[00m\] '
else
    PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w▶ '
fi
unset color_prompt

# Terminal title
case "$TERM" in
xterm*|rxvt*)
    PS1="\[\e]0;${debian_chroot:+($debian_chroot)}SodaSuicide Framework - \u@\h: \w\a\]$PS1"
    ;;
*)
    ;;
esac

# =============================================================================
# COLOR SUPPORT AND BASIC ALIASES
# =============================================================================

# Enable color support
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

# Enhanced ls aliases with cyberpunk flair
alias ll='ls -alF --color=auto | sort -n'
alias la='ls -A --color=auto | sort -n'
alias l='ls -CF --color=auto | sort -n'

# Find aliases
alias ff='find "$PWD" -type f | sort -n'
alias fd='find "$PWD" -type d | sort -n'

# System monitoring aliases
alias h='htop'
alias nw='watch -n 0.1 nvidia-smi'

# Git aliases for quick commits
alias g.='git add .'
alias gu='git add -u'
alias gsm='git commit -S -m "autonomous update"'
alias gp='git push'
alias gpmn='git push main'
alias gpms='git push master'

# =============================================================================
# CONDA/MAMBA INITIALIZATION
# =============================================================================

# >>> conda initialize >>>
__conda_setup="$('/home/mrnob0dy666/miniconda3/bin/conda' 'shell.bash' 'hook' 2> /dev/null)"
if [ $? -eq 0 ]; then
    eval "$__conda_setup"
else
    if [ -f "/home/mrnob0dy666/miniconda3/etc/profile.d/conda.sh" ]; then
        . "/home/mrnob0dy666/miniconda3/etc/profile.d/conda.sh"
    else
        export PATH="/home/mrnob0dy666/miniconda3/bin:$PATH"
    fi
fi
unset __conda_setup
# <<< conda initialize <<<

# >>> mamba initialize >>>
export MAMBA_EXE='/home/mrnob0dy666/miniconda3/bin/mamba';
export MAMBA_ROOT_PREFIX='/home/mrnob0dy666/miniconda3';
__mamba_setup="$("$MAMBA_EXE" shell hook --shell bash --root-prefix "$MAMBA_ROOT_PREFIX" 2> /dev/null)"
if [ $? -eq 0 ]; then
    eval "$__mamba_setup"
else
    alias mamba="$MAMBA_EXE"
fi
unset __mamba_setup
# <<< mamba initialize <<<

# Add user-local bin to PATH
export PATH="$HOME/.local/bin:$PATH"

# =============================================================================
# SODASUICIDE FRAMEWORK CONFIGURATION 
# Autonomous Research and Fine-tuning Framework
# =============================================================================

# GPU Configuration (RTX 2080 Super + RTX 3060)
# IMPORTANT: VRAM cannot be pooled due to incompatible architectures!
export CUDA_DEVICE_ORDER=PCI_BUS_ID
export CUDA_VISIBLE_DEVICES=0,1  # RTX 3060 (12GB) = 0, RTX 2080 Super (8GB) = 1

# PyTorch optimizations for dual-GPU setup
export PYTORCH_CUDA_ALLOC_CONF=max_split_size_mb:128
export TORCH_USE_CUDA_DSA=1
export CUDA_LAUNCH_BLOCKING=0
export TOKENIZERS_PARALLELISM=false
export OMP_NUM_THREADS=4

# HuggingFace cache (optimized for Windows drive access)
export HF_HOME=/mnt/c/models/.cache/huggingface
export TRANSFORMERS_CACHE=/mnt/c/models/.cache/transformers

# SODASUICIDE framework paths
export SODASUICIDE_HOME="/home/mrnob0dy666/sodasuicide"
export SODASUICIDE_CONFIG="$SODASUICIDE_HOME/config/sodasuicide_optimized.yaml"
export SODASUICIDE_DATA="$SODASUICIDE_HOME/data"
export SODASUICIDE_MODELS="$SODASUICIDE_HOME/models"

# Sacred Qwen3 Template Configuration (IMMUTABLE!)
export QWEN3_TEMPLATE_PATH="$SODASUICIDE_HOME/sodasuicide/templates/SACRED_QWEN3_CHAT_TEMPLATE.TXT"
export SODASUICIDE_TEMPLATE_MODE="qwen3"  # Default to sacred Qwen3 template

# T-CPDL Processor Configuration
export TCPDL_THRESHOLD=0.5
export TCPDL_ENHANCEMENT_LEVEL="standard"

# Model paths
export SODASUICIDE_BASE_MODEL="/home/mrnob0dy666/K5"

# =============================================================================
# GPU MANAGEMENT ALIASES
# =============================================================================

alias gc0='export CUDA_VISIBLE_DEVICES=0; echo "Using RTX 2080 Super (8GB) - Secondary for QLora"'
alias gc1='export CUDA_VISIBLE_DEVICES=1; echo "Using RTX 3060 (12GB) - Primary for larger models"'
alias gcboth='export CUDA_VISIBLE_DEVICES=0,1; echo "Using both GPUs (NO POOLING - separate tasks only)"'
alias gcstat='nvidia-smi --query-gpu=index,name,memory.used,memory.total,utilization.gpu --format=csv'
alias gclook='watch -n 0.5 "nvidia-smi --query-gpu=index,name,memory.used,memory.total,utilization.gpu --format=csv"'
alias gck='sudo pkill -f python; echo "💀 Killed all Python processes"'

# =============================================================================
# SODASUICIDE CORE ALIASES
# =============================================================================

# Main CLI commands
alias 𐑕𐑴𐑕𐑵𐑧𐑯𐑝𐑲𐑮𐑴𐑥𐑧𐑯𐑑𐑳𐑤='./sosu-environmental'
alias 𐑕𐑴𐑕𐑵𐑭𐑐𐑑𐑦𐑥𐑲𐑟𐑪𐑛='./sosu-optimized'
alias 𐑕𐑴𐑕𐑵='sodasuicide --verbose'
alias sosu='sodasuicide --verbose'
alias sodasuicide-auto='sodasuicide --autonomous --verbose'
alias sosu-auto='sodasuicide --auto --verbose'
alias sosu-interactive='sodasuicide --verbose'

# Quick start aliases
alias sosu-init='sodasuicide --create-config'
alias sosu-status='sodasuicide --help'  # Will show current status in real implementation

# Template management
alias sosu-template='sodasuicide --template'
alias sosu-qwen3='sodasuicide --template qwen3 --verbose'
alias sosu-qwen3-base='sodasuicide --template qwen3_base --verbose'

# Configuration aliases
alias sosuconfig='cat $SODASUICIDE_CONFIG'
alias sosuconfig-edit='nano $SODASUICIDE_CONFIG'
alias sosuconfig-backup='cp $SODASUICIDE_CONFIG $SODASUICIDE_CONFIG.backup.$(date +%Y%m%d_%H%M%S)'

# =============================================================================
# AUTONOMOUS OPERATION ALIASES 
# =============================================================================

# Autonomous modes
alias sosu-autonomous='sodasuicide --autonomous --verbose'
alias sosu-cyber='sosu-autonomous --template qwen3'
alias sosu-thinking='export SODASUICIDE_TEMPLATE_MODE=qwen3; sosu-autonomous'

# Research cycles
alias sosu-cycle='sodasuicide --single-cycle --verbose'
alias sosu-research='sodasuicide --research-only --verbose'
alias sosu-train='sodasuicide --training-only --verbose'

# T-CPDL operations
alias sosu-tcpdl='sodasuicide --tcpdl-analysis --verbose'
alias sosu-temporal='sosu-tcpdl --enhancement-level aggressive'

# =============================================================================
# ADAPTER AND FUSION MANAGEMENT 
# =============================================================================

alias sosu-adapters='ls -la $SODASUICIDE_ADAPTERS | tail -20'
alias sosu-fusion='sodasuicide --adapter-fusion --verbose'
alias sosu-merge='sodasuicide --merge-adapters --verbose'
alias sosu-export='sodasuicide --export-adapters --verbose'

# Adapter utilities
alias sosu-adapter-list='find $SODASUICIDE_ADAPTERS -name "*.safetensors" -o -name "*.bin" | head -20'
alias sosu-adapter-latest='ls -t $SODASUICIDE_ADAPTERS | head -5'
alias sosu-adapter-size='du -sh $SODASUICIDE_ADAPTERS/*'

# =============================================================================
# TRAINING CONFIGURATION ALIASES 🏋️‍♂
# =============================================================================

# GPU-specific training
alias sosu-train-3060='gpu3060 && sodasuicide --training-only --gpu-id 0 --verbose'
alias sosu-train-2080='gpu2080 && sodasuicide --training-only --gpu-id 0 --verbose'

# Training shortcuts
alias sosu-qlora='sodasuicide --qlora-training --verbose'
alias sosu-burst='sodasuicide --burst-training --verbose'
alias sosu-resume='sodasuicide --resume-training --verbose'

# =============================================================================
# MONITORING AND LOGGING 
# =============================================================================

alias sosu-logs='ls -la $SODASUICIDE_LOGS | tail -20'
alias sosu-tail='tail -f $SODASUICIDE_LOGS/sodasuicide_$(date +%Y%m%d).log'
alias sosu-errors='grep -i error $SODASUICIDE_LOGS/*.log | tail -20'
alias sosu-warnings='grep -i warning $SODASUICIDE_LOGS/*.log | tail -20'
alias sosu-performance='grep -i "performance\|metrics\|loss" $SODASUICIDE_LOGS/*.log | tail -10'

# SESSION management
alias sosu-SESSIONs='ls -la $SODASUICIDE_SESSIONS | tail -10'
alias sosu-SESSION-latest='ls -t $SODASUICIDE_SESSIONS | head -1'
alias sosu-SESSION-active='ps aux | grep sodasuicide'

# =============================================================================
# DATA AND OUTPUT MANAGEMENT 
# =============================================================================

alias sosu-output='ls -la $SODASUICIDE_OUTPUT | tail -10'
alias sosu-data='ls -la $SODASUICIDE_DATA | tail -10'
alias sosu-models='ls -la $SODASUICIDE_MODELS'
alias sosu-exports='ls -la $SODASUICIDE_EXPORTS | tail -10'
alias sosu-backups='ls -la $SODASUICIDE_BACKUPS | tail -5'

# Cleanup aliases
alias sosu-clean-logs='find $SODASUICIDE_LOGS -name "*.log" -mtime +7 -delete'
alias sosu-clean-cache='rm -rf $SODASUICIDE_CACHE/*'
alias sosu-clean-temp='find $SODASUICIDE_HOME -name "*.tmp" -delete'
alias sosu-clean-all='sosu-clean-logs && sosu-clean-cache && sosu-clean-temp'

# =============================================================================
# DEVELOPMENT AND TESTING 
# =============================================================================

alias sosu-test='pytest $SODASUICIDE_HOME/tests/ -v'
alias sosu-test-core='pytest $SODASUICIDE_HOME/tests/test_core/ -v'
alias sosu-test-tcpdl='pytest $SODASUICIDE_HOME/tests/test_tcpdl/ -v'
alias sosu-lint='black $SODASUICIDE_HOME/sodasuicide/ && isort $SODASUICIDE_HOME/sodasuicide/'

# Profiling and monitoring
alias sosu-profile='python -m cProfile -s cumulative'
alias sosu-memory='python -m memory_profiler'

# =============================================================================
# UTILITY FUNCTIONS 
# =============================================================================

# Quick autonomous SESSION with custom parameters
sosu_quick_auto() {
    local autonomy_level="${1:-0.8}"
    local max_cycles="${2:-10}"
    
    echo -e "${NEON_GREEN} Starting SodaSuicide Autonomous SESSION${NC}"
    echo -e "${NEON_BLUE} Autonomy Level: $autonomy_level${NC}"
    echo -e "${NEON_PINK} Max Cycles: $max_cycles${NC}"
    
    sodasuicide --autonomous --autonomy-level "$autonomy_level" --max-cycles "$max_cycles" --verbose
}

# Batch adapter fusion
sosu_batch_fusion() {
    local strategy="${1:-weighted_average}"
    local min_adapters="${2:-2}"
    
    echo -e "${NEON_ORANGE}🔗 Batch Adapter Fusion${NC}"
    echo -e "${NEON_PURPLE}📊 Strategy: $strategy${NC}"
    
    sodasuicide --adapter-fusion --fusion-strategy "$strategy" --min-adapters "$min_adapters" --verbose
}

# System health check
sosu_health_check() {
    echo -e "${NEON_GREEN}╔════════════════════════════╗${NC}"
    echo -e "${NEON_GREEN}║  SODASUICIDE HEALTH CHECK  ║${NC}"
    echo -e "${NEON_GREEN}╚════════════════════════════╝${NC}"
    
    echo -e "${NEON_BLUE}📊 GPU Status:${NC}"
    nvidia-smi --query-gpu=name,memory.used,memory.total --format=csv,noheader
    
    echo -e "${NEON_BLUE}📁 Disk Usage:${NC}"
    df -h $SODASUICIDE_HOME | tail -1
    
    echo -e "${NEON_BLUE}🔧 Environment:${NC}"
    echo "  Active Environment: $(conda info --envs | grep '*' | awk '{print $1}')"
    echo "  Python Version: $(python --version)"
    echo "  PyTorch Version: $(python -c "import torch; print(torch.__version__)" 2>/dev/null || echo 'Not installed')"
    
    echo -e "${NEON_BLUE}📈 Recent Activity:${NC}"
    [ -f "$SODASUICIDE_LOGS/sodasuicide_$(date +%Y%m%d).log" ] && tail -3 "$SODASUICIDE_LOGS/sodasuicide_$(date +%Y%m%d).log" || echo "  No recent activity"
}

# Template validation function
sosu_validate_template() {
    local file="$1"
    if [ -z "$file" ]; then
        echo -e "${CYBER_RED}Usage: sosu_validate_template <training_file.jsonl>${NC}"
        return 1
    fi
    
    python -c "
from sodasuicide.templates import Qwen3Template
import json

template = Qwen3Template()
with open('$file', 'r') as f:
    valid_count = 0
    total_count = 0
    for i, line in enumerate(f):
        total_count += 1
        sample = json.loads(line)
        if template.validate_training_sample(sample):
            valid_count += 1
            print(f'✅ Valid sample at line {i+1}')
        else:
            print(f'❌ Invalid sample at line {i+1}')
    
    print(f'\\n📊 Validation Summary: {valid_count}/{total_count} samples valid')
"
}

# Performance monitoring
sosu_monitor() {
    local duration="${1:-60}"
    
    echo -e "${NEON_GREEN}📊 Monitoring SodaSuicide for $duration seconds...${NC}"
    echo -e "${NEON_BLUE}Press Ctrl+C to stop${NC}"
    
    watch -n 2 "
    echo -e '${NEON_GREEN}SodaSuicide Performance Monitor${NC}'
    echo -e '${NEON_BLUE}================================${NC}'
    nvidia-smi --query-gpu=name,memory.used,memory.total,utilization.gpu --format=csv,noheader
    echo ''
    echo -e '${NEON_ORANGE}Active Processes:${NC}'
    ps aux | grep '[s]odasuicide' | head -5
    echo ''
    echo -e '${NEON_PURPLE}Memory Usage:${NC}'
    free -h | grep 'Mem:'
    "
}

# =============================================================================
# PROJECT NAVIGATION 🫵💀
# =============================================================================

alias sosuhome='cd $SODASUICIDE_HOME'
alias sosudata='cd $SODASUICIDE_DATA'
alias sosulogs='cd $SODASUICIDE_LOGS'
alias sosuconfig-dir='cd $SODASUICIDE_HOME/config'

# =============================================================================
# AUTO-INITIALIZATION 💊  
# =============================================================================

# Create necessary directories
for dir in "$SODASUICIDE_DATA" "$SODASUICIDE_MODELS" "$SODASUICIDE_ADAPTERS" "$SODASUICIDE_OUTPUT" "$SODASUICIDE_SESSIONS" "$SODASUICIDE_LOGS" "$SODASUICIDE_CACHE" "$SODASUICIDE_EXPORTS" "$SODASUICIDE_BACKUPS"; do
    [ ! -d "$dir" ] && mkdir -p "$dir"
done

# Auto-activate sodasuicide environment
if command -v mamba &> /dev/null; then
    if [ "$CONDA_DEFAULT_ENV" != "sodasuicide" ]; then
        mamba activate sodasuicide 2>/dev/null || {
            echo -e "${CYBER_RED}⚠️  Failed to activate sodasuicide environment${NC}"
            echo -e "${NEON_ORANGE}💡 Run: mamba create -n sodasuicide python=3.10${NC}"
            echo -e "${NEON_ORANGE}💡 Then: mamba activate sodasuicide${NC}"
            echo -e "${NEON_ORANGE}💡 Finally: pip install -e .${NC}"
        }
    fi
fi

# Navigate to project directory
if [ -d "$SODASUICIDE_HOME" ]; then
    cd "$SODASUICIDE_HOME"
fi

# =============================================================================
# CYBERPUNK STARTUP BANNER   💀⚡
# =============================================================================

echo -e "${NEON_GREEN}"
echo "═══════════════════════════════════════════════════════════"
echo "                   𐑕𐑴𐑛𐑳𐑕𐑵𐑦𐑕𐑲𐑛   𐑓𐑮𐑱𐑥𐑢𐑻𐑒"
echo ""
echo "     ███████╗ ██████╗ ██████╗  █████╗ ███████╗██╗   ██╗"
echo "     ██╔════╝██╔═══██╗██╔══██╗██╔══██╗██╔════╝██║   ██║"
echo "     ███████╗██║   ██║██║  ██║███████║███████╗██║   ██║"
echo "     ╚════██║██║   ██║██║  ██║██╔══██║╚════██║██║   ██║"
echo "     ███████║╚██████╔╝██████╔╝██║  ██║███████║╚██████╔╝"
echo "     ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝"
echo ""
echo "                      𐑷𐑑𐑩𐑯𐑪𐑥𐑳𐑕   𐑮𐑰𐑕𐑻𐑗"
echo "═══════════════════════════════════════════════════════════"
echo -e "${NC}"

echo -e "${NEON_BLUE}╔════════════════════════════════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${NEON_BLUE}║                           SYSTEM STATUS                                                                ║${NC}"
echo -e "${NEON_BLUE}╠════════════════════════════════════════════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${NEON_BLUE}║${NC} ${NEON_ORANGE}Directory:${NC} $(pwd)"
echo -e "${NEON_BLUE}║${NC} ${NEON_ORANGE}Environment:${NC} $(conda info --envs 2>/dev/null | grep '*' | awk '{print $1}' || echo 'None')"
echo -e "${NEON_BLUE}║${NC} ${NEON_ORANGE}GPUs:${NC} $(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | tr '\n' ', ' | sed 's/,$//' || echo 'None detected')"
echo -e "${NEON_BLUE}║${NC} ${NEON_ORANGE}Sacred Template:${NC} $QWEN3_TEMPLATE_PATH"
echo -e "${NEON_BLUE}║${NC} ${NEON_ORANGE}Template Mode:${NC} $SODASUICIDE_TEMPLATE_MODE"
echo -e "${NEON_BLUE}║${NC} ${NEON_ORANGE}T-CPDL Threshold:${NC} $TCPDL_THRESHOLD"
echo -e "${NEON_BLUE}║${NC} ${NEON_ORANGE}Enhancement Level:${NC} $TCPDL_ENHANCEMENT_LEVEL"
echo -e "${NEON_BLUE}╠═════════════════════════════════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${NEON_BLUE}║${NC} ${NEON_PINK}Quick Start:${NC}"
echo -e "${NEON_BLUE}║${NC}   ${NEON_GREEN}sosu${NC} ====================| Interactive mode"
echo -e "${NEON_BLUE}║${NC}   ${NEON_GREEN}sosu-auto${NC} ===============| Autonomous mode"
echo -e "${NEON_BLUE}║${NC}   ${NEON_GREEN}sosu-health-check${NC} =======| System diagnostics"
echo -e "${NEON_BLUE}║${NC}   ${NEON_GREEN}sosu-cycle${NC} ==============| Single research cycle"
echo -e "${NEON_BLUE}║${NC}   ${NEON_GREEN}gpustat${NC} =================| GPU monitoring"
echo -e "${NEON_BLUE}╚═════════════════════════════════════════════════════╝${NC}"

# Check if sodasuicide is installed
if ! command -v sodasuicide &> /dev/null; then
    echo -e "${CYBER_RED}⚠️  SodaSuicide not installed. Run: pip install -e .${NC}"
fi

# GPG and display settings for WSL2
export GPG_TTY=$(tty)
export DISPLAY=$(cat /etc/resolv.conf 2>/dev/null | grep nameserver | awk '{print $2}' 2>/dev/null):0.0 2>/dev/null || export DISPLAY=:0
export QT_QPA_PLATFORM=xcb

echo -e "${DARK_GRAY}════════════════════════════════════════════════════════════════════════════${NC}"
echo ""
