#!/bin/sh
# Post-install script for Secure Infrastructure packages

set -e

# Create secureinfra group if it doesn't exist
if ! getent group secureinfra >/dev/null 2>&1; then
    groupadd --system secureinfra
fi

# Create secureinfra user if it doesn't exist
if ! getent passwd secureinfra >/dev/null 2>&1; then
    useradd --system --gid secureinfra --shell /sbin/nologin \
        --home-dir /var/lib/secureinfra --no-create-home secureinfra
fi

# Create data directory
mkdir -p /var/lib/secureinfra
chown secureinfra:secureinfra /var/lib/secureinfra
chmod 750 /var/lib/secureinfra

# Create config directory if it doesn't exist
mkdir -p /etc/secureinfra
chmod 755 /etc/secureinfra

# Reload systemd to pick up new unit files
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi

echo "Secure Infrastructure package installed successfully."
echo "Configure the service in /etc/secureinfra/ before starting."
