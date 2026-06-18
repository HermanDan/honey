#!/usr/bin/env bash
set -euo pipefail

# --- Paths ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COWRIE_DIR="${SCRIPT_DIR}/cowrie"
VENV_DIR="${COWRIE_DIR}/cowrie-env"
LOG_DIR="${COWRIE_DIR}/var/log/cowrie"
PID_DIR="${COWRIE_DIR}/var/run"
FSPICKLE="${COWRIE_DIR}/share/cowrie/fs.pickle"

# --- Sanity checks ---
if [ ! -d "$COWRIE_DIR" ]; then
  echo "Error: Cowrie directory not found at: $COWRIE_DIR"
  exit 1
fi

if [ ! -d "$VENV_DIR" ]; then
  echo "Error: Virtualenv not found at: $VENV_DIR"
  echo "Create it once with: python3.10 -m venv $VENV_DIR"
  exit 1
fi

cd "$COWRIE_DIR"

# --- Activate venv ---
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"
echo "Using venv: ${VIRTUAL_ENV}"

# --- Warn-only checks (do not auto-fix) ---
if [ ! -f "$FSPICKLE" ]; then
  echo "Warning: fs.pickle missing at: $FSPICKLE"
  echo "         (Not generating automatically.)"
fi

if [ ! -f "${COWRIE_DIR}/etc/cowrie.cfg" ]; then
  echo "Warning: etc/cowrie.cfg missing."
  echo "         If needed: cp etc/cowrie.cfg.dist etc/cowrie.cfg"
fi

# --- Determine status safely (avoid 'running' substring bug) ---
STATUS="$(bin/cowrie status 2>&1 || true)"

if echo "$STATUS" | grep -qi "not running"; then
  echo "Cowrie is not running; starting..."
  bin/cowrie start || true
  sleep 2
elif echo "$STATUS" | grep -qi "is running"; then
  echo "Cowrie already running."
else
  echo "Unknown cowrie status output:"
  echo "$STATUS"
  echo "Attempting to start anyway..."
  bin/cowrie start || true
  sleep 2
fi

# --- Final status ---
echo
echo "Cowrie status:"
bin/cowrie status 2>&1 || true

# --- Port check (default Cowrie SSH is 2222) ---
echo
echo "Listening check (port 2222):"
if ss -lntp 2>/dev/null | grep -q ":2222"; then
  ss -lntp | grep ":2222" || true
else
  echo "Port 2222 not detected listening."
  echo "Check cowrie.cfg for listen_port or look for errors in logs."
fi

# --- If not running, show logs to help debugging ---
STATUS2="$(bin/cowrie status 2>&1 || true)"
if echo "$STATUS2" | grep -qi "not running"; then
  echo
  echo "Cowrie failed to start or exited. Recent logs:"
  if [ -f "${LOG_DIR}/cowrie.log" ]; then
    tail -n 120 "${LOG_DIR}/cowrie.log"
  else
    echo "No cowrie.log found at ${LOG_DIR}/cowrie.log"
    echo "Contents of log dir:"
    ls -lah "$LOG_DIR" || true
  fi

  echo
  echo "PID dir contents:"
  ls -lah "$PID_DIR" || true
  exit 1
fi

echo
echo "Log dir: ${LOG_DIR}"
echo "Done."
