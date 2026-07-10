#!/usr/bin/env bash
# © Amine NAHLI | 2026
# install.sh
#
# Zero-friction install script for Smart Network Mapper.
# Anyone who clones this project should be able to run
# `./install.sh` and end up with a working setup,
# regardless of whether they have uv or just installed yet.
#
# Run with:  ./install.sh
# Or:        bash install.sh

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1" >&2; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }

check_python() {
    info "Checking for Python 3.13+..."

    if ! command -v python3 &>/dev/null; then
        error "python3 not found. Please install Python 3.13 or newer."
        exit 1
    fi

    local version
    version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')

    local major minor
    major=$(echo "$version" | cut -d. -f1)
    minor=$(echo "$version" | cut -d. -f2)

    if (( major < 3 )) || { (( major == 3 )) && (( minor < 13 )); }; then
        error "Python 3.13+ is required, found Python $version"
        exit 1
    fi

    success "Python $version detected"
}

install_uv() {
    if command -v uv &>/dev/null; then
        success "uv already installed ($(uv --version))"
        return 0
    fi

    info "Installing uv (Python package manager)..."
    curl -LsSf https://astral.sh/uv/install.sh | sh

    export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

    if ! command -v uv &>/dev/null; then
        error "uv install completed but \`uv\` is still not on PATH."
        exit 1
    fi
    success "uv installed"
}

install_just() {
    if command -v just &>/dev/null; then
        success "just already installed ($(just --version))"
        return 0
    fi

    info "Installing just (command runner)..."
    mkdir -p "$HOME/.local/bin"
    curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh \
        | bash -s -- --to "$HOME/.local/bin"

    export PATH="$HOME/.local/bin:$PATH"
    success "just installed"
}

check_npcap() {
    if [[ "$(uname -o 2>/dev/null)" == "Msys" ]] || [[ "$(uname -s)" == MINGW* ]]; then
        if [ -d "/c/Program Files/Npcap" ] || [ -d "/c/Windows/System32/Npcap" ]; then
            success "Npcap detected"
        else
            warn "Npcap not found. Install from https://npcap.com/#download"
            warn "Npcap is required for advanced network features (ARP/Scapy)."
        fi
    fi
}

project_setup() {
    info "Running 'just setup'..."
    just setup
}

main() {
    echo ""
    echo "================================================"
    echo "  Smart Network Mapper — install"
    echo "  © Amine NAHLI — MIT License"
    echo "================================================"
    echo ""

    check_python
    install_uv
    install_just
    check_npcap
    project_setup

    echo ""
    echo "================================================"
    success "Install complete!"
    echo "================================================"
    echo ""
    echo "Next steps:"
    echo "  just run          # Launch the GUI scanner"
    echo "  just test         # Run tests"
    echo "  just lint         # Check code quality"
    echo "  just format       # Auto-format code"
    echo ""
    echo "Environment variables (optional):"
    echo "  Copy .env.example to .env and fill in your keys"
    echo "  GROQ_API_KEY      — AI audit reports (Groq Llama-3.3-70b)"
    echo "  TELEGRAM_BOT_TOKEN — Telegram bot automation"
    echo ""
}

main "$@"
