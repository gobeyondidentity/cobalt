#!/bin/sh
# Post-install script for sentry-doca package

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

# Update ldconfig cache for DOCA libraries
if [ -f /etc/ld.so.conf.d/doca-x86_64.conf ]; then
    ldconfig
fi

# Create default environment file if it doesn't exist
if [ ! -f /etc/default/sentry ]; then
    cat > /etc/default/sentry << 'EOF'
# Sentry environment configuration
# Uncomment and configure options as needed

# Force DOCA ComCh transport (requires BlueField PCIe connection)
# SENTRY_FORCE_COMCH=1

# PCI address of BlueField device (required for ComCh)
# Example: SENTRY_DOCA_PCI_ADDR=0000:01:00.0
# SENTRY_DOCA_PCI_ADDR=

# ComCh server name (default: secure-infra)
# SENTRY_DOCA_SERVER_NAME=secure-infra

# Path to host authentication key
# SENTRY_AUTH_KEY=/etc/secureinfra/host-agent.key
EOF
    chmod 644 /etc/default/sentry
fi

# Reload systemd to pick up new unit files
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi

echo "sentry-doca package installed successfully."
echo "Configure /etc/default/sentry with your BlueField PCI address before starting."
