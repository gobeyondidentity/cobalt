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

# Create data directories
mkdir -p /var/lib/secureinfra
chown secureinfra:secureinfra /var/lib/secureinfra
chmod 750 /var/lib/secureinfra

# Aegis-specific data directory (aegis runs as root on DPU)
mkdir -p /var/lib/aegis
chmod 750 /var/lib/aegis

# Create config directory if it doesn't exist
mkdir -p /etc/secureinfra
chmod 755 /etc/secureinfra

# Generate self-signed TLS certificates if not present
CERT_DIR="/etc/secureinfra"
CERT_FILE="$CERT_DIR/server.crt"
KEY_FILE="$CERT_DIR/server.key"

if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo "Generating self-signed TLS certificates..."
    openssl req -x509 -newkey rsa:4096 -keyout "$KEY_FILE" -out "$CERT_FILE" \
        -sha256 -days 365 -nodes \
        -subj "/CN=secureinfra/O=Beyond Identity/C=US" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
    chmod 600 "$KEY_FILE"
    chmod 644 "$CERT_FILE"
    chown secureinfra:secureinfra "$KEY_FILE" "$CERT_FILE"
    echo "TLS certificates generated at $CERT_DIR"
fi

# Migration: update old systemd overrides that use deprecated flags
AEGIS_OVERRIDE="/etc/systemd/system/aegis.service.d/override.conf"
if [ -f "$AEGIS_OVERRIDE" ]; then
    if grep -q -- '--control-plane' "$AEGIS_OVERRIDE"; then
        echo "Migrating aegis systemd override: --control-plane -> --server"
        sed -i 's/--control-plane/--server/g' "$AEGIS_OVERRIDE"
    fi
    if grep -q -- '--local-api' "$AEGIS_OVERRIDE"; then
        echo "Migrating aegis systemd override: removing deprecated --local-api flag"
        sed -i 's/--local-api[[:space:]]*//g' "$AEGIS_OVERRIDE"
    fi
    if grep -q -- '--config' "$AEGIS_OVERRIDE"; then
        echo "WARNING: aegis override uses --config which is no longer supported."
        echo "Please update $AEGIS_OVERRIDE to use CLI flags instead."
        echo "See /etc/secureinfra/aegis.env for configuration options."
    fi
fi

# Reload systemd to pick up new unit files
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi

echo "Secure Infrastructure package installed successfully."
echo "Configure the service in /etc/secureinfra/aegis.env before starting."
