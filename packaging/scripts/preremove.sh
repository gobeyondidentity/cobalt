#!/bin/sh
# Pre-remove script for Secure Infrastructure packages

set -e

# Stop and disable the service if it exists and is running
# The service name is passed as the first argument by nfpm
SERVICE_NAME="${1:-}"

if [ -n "$SERVICE_NAME" ] && command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl stop "$SERVICE_NAME" || true
    fi
    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl disable "$SERVICE_NAME" || true
    fi
fi
