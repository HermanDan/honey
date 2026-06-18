#!/bin/bash

set -e

COWRIE_DIR="$HOME/honey/cowrie"
PICKLE_PATH="$COWRIE_DIR/var/fs.pickle"
HONEYFS_PATH="$COWRIE_DIR/honeyfs"
COWRIE_BIN="$COWRIE_DIR/bin/cowrie"
CREATEFS_BIN="$COWRIE_DIR/bin/createfs"

echo " [1] Rebuilding fs.pickle from honeyfs..."
cd "$COWRIE_DIR"
$CREATEFS_BIN -o "$PICKLE_PATH" "$HONEYFS_PATH"

echo " [2] Verifying key /root decoy files..."
declare -a files=("flag.txt" "id_rsa" "secret.txt" ".bashrc" ".bash_history")

for file in "${files[@]}"; do
    FILE_PATH="$HONEYFS_PATH/root/$file"
    if [ -f "$FILE_PATH" ]; then
        echo " Found: $FILE_PATH"
    else
        echo " MISSING: $FILE_PATH"
    fi
done

echo " [3] Stopping Cowrie (if running)..."
$COWRIE_BIN stop || true
sleep 2

# Kill any leftover twistd processes
pkill -f twistd || true

echo " [4] Starting Cowrie again..."
$COWRIE_BIN start
sleep 2

echo " [5] Fake FS sync complete. Try SSH again:"
echo "    ssh root@localhost -p 2222"
echo "Then run: ls /root && cat /root/flag.txt"
