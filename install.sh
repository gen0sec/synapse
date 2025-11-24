#!/bin/sh

VERSION=0.2.1
BRANCH=main

# Install dependencies
echo "Installing dependencies..."
apt-get update -qq
apt-get install -yqq curl sed clamav-daemon redis-server

# Setup ClamAV

echo "Setting up ClamAV..."
curl -fSL https://raw.githubusercontent.com/gen0sec/synapse/refs/heads/${BRANCH}/others/clamd/clamd.conf -o /etc/clamav/clamd.conf
mkdir -p /etc/systemd/system/clamav-daemon.socket.d
curl -fSL https://raw.githubusercontent.com/gen0sec/synapse/refs/heads/${BRANCH}/others/systemd/clamd/override.conf -o /etc/systemd/system/clamav-daemon.socket.d/override.conf
systemctl daemon-reload
systemctl enable clamav-daemon
systemctl restart clamav-daemon
systemctl status clamav-daemon

echo "ClamAV setup complete."
sleep 1

# Install synapse
echo "Installing synapse ${VERSION} for $(arch)..."
curl -fSL https://github.com/gen0sec/synapse/releases/download/v${VERSION}/synapse-$(arch)-unknown-linux-gnu.tar.gz -o /tmp/synapse-$(arch)-unknown-linux-gnu.tar.gz
tar -C /usr/local/bin -xzf /tmp/synapse-$(arch)-unknown-linux-gnu.tar.gz

# Install service
echo "Installing service..."
curl -fSL https://raw.githubusercontent.com/gen0sec/synapse/refs/heads/${BRANCH}/others/systemd/synapse.service -o /etc/systemd/system/synapse.service
systemctl daemon-reload

# Create directories
echo "Creating directories..."
mkdir -p /var/log/synapse /var/run/synapse /var/lib/synapse /etc/synapse

# Create config file
echo "Creating config file..."
curl -fSL https://raw.githubusercontent.com/gen0sec/synapse/refs/heads/${BRANCH}/config_example.yaml -o /etc/synapse/config.yaml
chmod 640 /etc/synapse/config.yaml
curl -fSL https://raw.githubusercontent.com/gen0sec/synapse/refs/heads/${BRANCH}/upstreams_example.yaml -o /etc/synapse/upstreams.yaml
chmod 644 /etc/synapse/upstreams.yaml

# Enable and start service
echo "Enabling and starting service..."
systemctl enable synapse

echo "Before starting the service, you need to add your API key to the config file /etc/synapse/config.yaml."
sleep 1
echo "You can get your API key from https://dash.gen0sec.com/settings/api-keys."
sleep 1
echo "Then run 'systemctl start synapse' to start the service."
