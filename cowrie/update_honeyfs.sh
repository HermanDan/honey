#!/bin/bash

HONEYFS_DIR="honeyfs"
PICKLE_FILE="cowrie/src/cowrie/data/fs.pickle"

# Random generators
RANDOM_FLAG="FLAG{$(uuidgen)}"
RANDOM_AWS_KEY="AKIA$(head /dev/urandom | tr -dc A-Z0-9 | head -c16)"
RANDOM_AWS_SECRET="$(head /dev/urandom | tr -dc A-Za-z0-9/+= | head -c40)"
RANDOM_ADMIN_PASS="admin:$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c12)"
RANDOM_RSA_KEY="-----BEGIN OPENSSH PRIVATE KEY-----\n$(head /dev/urandom | base64 | head -c500)\n-----END OPENSSH PRIVATE KEY-----"

echo " Generating random decoy files..."

# Root folder decoys
mkdir -p $HONEYFS_DIR/root
echo "$RANDOM_FLAG" > $HONEYFS_DIR/root/flag.txt
echo -e "$RANDOM_RSA_KEY" > $HONEYFS_DIR/root/id_rsa

# Etc folder decoys
mkdir -p $HONEYFS_DIR/etc
cat <<EOF > $HONEYFS_DIR/etc/secrets.txt
AWS_ACCESS_KEY_ID=$RANDOM_AWS_KEY
AWS_SECRET_ACCESS_KEY=$RANDOM_AWS_SECRET
EOF

# Admin home decoys
mkdir -p $HONEYFS_DIR/home/admin
echo "$RANDOM_ADMIN_PASS" > $HONEYFS_DIR/home/admin/passwords.txt

# Timestamp marker
date > $HONEYFS_DIR/.last_updated

echo "Random decoy files generated."

# Remove old fs.pickle
rm -f var/fs.pickle
echo "Rebuilding virtual filesystem pickle..."
python bin/createfs -o $PICKLE_FILE $HONEYFS_DIR

if [ $? -ne 0 ]; then
    echo "Error rebuilding fs.pickle"
    exit 1
fi

echo " Pickle rebuilt: $PICKLE_FILE"

echo " Stopping Cowrie..."
bin/cowrie stop
rm -f var/run/cowrie.pid

echo " Cowrie stopped."

echo " Starting Cowrie..."
bin/cowrie start

if [ $? -eq 0 ]; then
    echo " Cowrie restarted successfully!"
else
    echo " Failed to start Cowrie."
fi


