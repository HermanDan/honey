#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COWRIE_DIR="${SCRIPT_DIR}/cowrie"
VENV_DIR="${COWRIE_DIR}/cowrie-env"
LOG_DIR="${COWRIE_DIR}/var/log/cowrie"
FSPICKLE="${COWRIE_DIR}/share/cowrie/fs.pickle"

echo "=== Cowrie Honeypot Setup ==="

# --- Sanity ---
if [ ! -d "$COWRIE_DIR" ]; then
  echo "ERROR: Cowrie directory not found at $COWRIE_DIR"
  exit 1
fi

cd "$COWRIE_DIR"

# --- Python ---
if ! python3.10 --version >/dev/null 2>&1; then
  echo "ERROR: Python 3.10 not found."
  echo "Install with:"
  echo "  sudo apt update && sudo apt install -y python3.10 python3.10-venv"
  exit 1
fi

# --- System deps (safe to re-run) ---
echo "Installing system dependencies..."
sudo apt update
sudo apt install -y \
  git \
  build-essential \
  libssl-dev \
  libffi-dev \
  python3.10-venv \
  python3-pip

# --- Virtual environment ---
if [ ! -d "$VENV_DIR" ]; then
  echo "Creating virtualenv..."
  python3.10 -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
echo "Using venv: $VIRTUAL_ENV"

# --- Python deps ---
echo "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# --- Directory structure ---
mkdir -p "$LOG_DIR"
mkdir -p var/run

# --- Config checks ---
if [ ! -f "etc/cowrie.cfg" ]; then
  echo "WARNING: etc/cowrie.cfg missing."
  echo "Creating from default template."
  cp etc/cowrie.cfg.dist etc/cowrie.cfg
fi

# --- fs.pickle (warn only) ---
if [ ! -f "$FSPICKLE" ]; then
  echo "WARNING: fs.pickle missing at:"
  echo "  $FSPICKLE"
  echo "Cowrie can run, but filesystem emulation may be limited."
  echo "Generate ONCE later using Cowrie's createfs tool if desired."
fi

# --- Permissions ---
chmod +x bin/cowrie

# --- Summary ---
echo
echo "=== Setup summary ==="
echo "Cowrie dir:   $COWRIE_DIR"
echo "Venv:         $VENV_DIR"
echo "Logs:         $LOG_DIR"
echo "Config:       etc/cowrie.cfg"
echo "fs.pickle:    $( [ -f "$FSPICKLE" ] && echo present || echo MISSING )"

echo
echo "Setup complete."
echo "Next step: run ./start_honeypot.sh"
