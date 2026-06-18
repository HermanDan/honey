#!/usr/bin/env bash
set -euo pipefail

PROFILE_FILE="${1:-}"
HOST="${2:-127.0.0.1}"
PORT="${3:-2222}"
USER="${4:-root}"

if [ -z "$PROFILE_FILE" ] || [ ! -f "$PROFILE_FILE" ]; then
  echo "Usage: $0 <profile_file> [host] [port] [user]"
  exit 1
fi

# Password via env var (recommended)
# Example: export COWRIE_PASS="whatever"
PASS="${COWRIE_PASS:-}"

if [ -z "$PASS" ]; then
  echo "Error: COWRIE_PASS is not set."
  echo "Set it like:"
  echo "  export COWRIE_PASS='yourpassword'"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIM_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
RUNS_DIR="${SIM_DIR}/runs"
mkdir -p "$RUNS_DIR"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
PROFILE_NAME="$(basename "$PROFILE_FILE" .txt)"
RUN_ID="${TS}_${PROFILE_NAME}"
META_FILE="${RUNS_DIR}/${RUN_ID}.meta.txt"

{
  echo "run_id=$RUN_ID"
  echo "timestamp_utc=$TS"
  echo "profile=$PROFILE_NAME"
  echo "profile_file=$PROFILE_FILE"
  echo "host=$HOST"
  echo "port=$PORT"
  echo "user=$USER"
} > "$META_FILE"

echo "Running profile '$PROFILE_NAME' on ${USER}@${HOST}:${PORT}"
echo "Run ID: $RUN_ID"
echo "Metadata: $META_FILE"
echo

# Send commands as if typed (CR at end), with small delays.
# This yields cowrie.command.input for each line.
{
  while IFS= read -r line || [ -n "$line" ]; do
    # skip blank lines and comments
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^# ]] && continue

    printf "%s\r" "$line"
    sleep 0.25
  done < "$PROFILE_FILE"

  printf "exit\r"
} | sshpass -p "$PASS" ssh -tt -p "$PORT" \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  "${USER}@${HOST}"

echo
echo "Done."
