#!/usr/bin/env bash
#
# Project Cobalt Package Installer
# Validates architecture requirements before delegating to Cloudsmith repository setup.
#
# Usage:
#   curl -1sLf 'https://raw.githubusercontent.com/gobeyondidentity/cobalt/main/scripts/install.sh' | sudo bash
#   curl -1sLf '...' | sudo bash -s aegis      # Install specific package
#   curl -1sLf '...' | sudo bash -s -- --help  # Show help
#

set -e

# Package architecture requirements
# aegis runs on BlueField DPU (ARM64 only)
# All other packages support both architectures
ARM64_ONLY_PACKAGES="aegis"

# Cloudsmith repository URLs
CLOUDSMITH_DEB="https://dl.cloudsmith.io/public/beyond-identity/secure-infra/cfg/setup/bash.deb.sh"
CLOUDSMITH_RPM="https://dl.cloudsmith.io/public/beyond-identity/secure-infra/cfg/setup/bash.rpm.sh"

# Colors (disabled if not a terminal)
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    RESET='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    RESET=''
fi

error() {
    echo -e "${RED}Error: $1${RESET}" >&2
    exit 1
}

warn() {
    echo -e "${YELLOW}Warning: $1${RESET}" >&2
}

info() {
    echo -e "${GREEN}$1${RESET}"
}

usage() {
    cat <<EOF
Project Cobalt Package Installer

Usage:
  install.sh [OPTIONS] [PACKAGE...]

Options:
  -h, --help     Show this help message
  --dry-run      Show what would be done without executing

Packages:
  aegis          DPU agent (arm64 only, requires BlueField hardware)
  sentry         Host agent
  bluectl        Admin CLI
  km             Operator CLI (KeyMaker)
  nexus          Control plane server
  dpuemu         DPU emulator for development

Examples:
  # Set up repository only (no package install)
  curl -1sLf 'URL' | sudo bash

  # Set up repository and install specific package
  curl -1sLf 'URL' | sudo bash -s aegis

  # Install multiple packages
  curl -1sLf 'URL' | sudo bash -s bluectl km

Architecture Notes:
  aegis requires arm64 (BlueField DPU). Attempting to install on x86_64/amd64
  will fail with a clear error message.

EOF
    exit 0
}

# Detect system architecture
# Returns: amd64, arm64, or the raw uname output
detect_arch() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)
            echo "amd64"
            ;;
        aarch64|arm64)
            echo "arm64"
            ;;
        *)
            echo "$arch"
            ;;
    esac
}

# Detect package manager type
# Returns: deb, rpm, or unknown
detect_package_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        echo "deb"
    elif command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then
        echo "rpm"
    else
        echo "unknown"
    fi
}

# Check if a package requires arm64
# Args: package name
# Returns: 0 if arm64 required, 1 otherwise
requires_arm64() {
    local pkg="$1"
    for arm_pkg in $ARM64_ONLY_PACKAGES; do
        if [[ "$pkg" == "$arm_pkg" ]]; then
            return 0
        fi
    done
    return 1
}

# Validate architecture for requested packages
# Args: list of package names
# Returns: 0 if all packages valid for current arch, exits with error otherwise
validate_packages() {
    local arch
    arch=$(detect_arch)

    for pkg in "$@"; do
        if requires_arm64 "$pkg" && [[ "$arch" != "arm64" ]]; then
            error "$pkg requires arm64 (BlueField DPU). Current architecture: $arch

The aegis agent runs on NVIDIA BlueField DPUs which use ARM64 processors.
It cannot be installed on x86_64/amd64 systems.

For development without hardware, use the DPU emulator:
  sudo apt install dpuemu   # Debian/Ubuntu
  sudo yum install dpuemu   # RHEL/Fedora"
        fi
    done
}

# Run the appropriate Cloudsmith setup script
# Args: deb or rpm
setup_repository() {
    local pkg_type="$1"
    local url

    case "$pkg_type" in
        deb)
            url="$CLOUDSMITH_DEB"
            ;;
        rpm)
            url="$CLOUDSMITH_RPM"
            ;;
        *)
            error "Unsupported package manager. This installer supports apt (deb) and yum/dnf (rpm)."
            ;;
    esac

    info "Setting up Beyond Identity package repository..."

    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[dry-run] Would execute: curl -1sLf '$url' | bash"
        return 0
    fi

    curl -1sLf "$url" | bash
}

# Install packages using the appropriate package manager
# Args: package manager type, list of packages
install_packages() {
    local pkg_type="$1"
    shift
    local packages=("$@")

    if [[ ${#packages[@]} -eq 0 ]]; then
        return 0
    fi

    info "Installing packages: ${packages[*]}"

    if [[ "$DRY_RUN" == "true" ]]; then
        case "$pkg_type" in
            deb)
                echo "[dry-run] Would execute: apt-get update && apt-get install -y ${packages[*]}"
                ;;
            rpm)
                echo "[dry-run] Would execute: yum install -y ${packages[*]}"
                ;;
        esac
        return 0
    fi

    case "$pkg_type" in
        deb)
            apt-get update
            apt-get install -y "${packages[@]}"
            ;;
        rpm)
            yum install -y "${packages[@]}"
            ;;
    esac
}

main() {
    local packages=()
    DRY_RUN="false"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                ;;
            --dry-run)
                DRY_RUN="true"
                shift
                ;;
            -*)
                error "Unknown option: $1. Use --help for usage."
                ;;
            *)
                packages+=("$1")
                shift
                ;;
        esac
    done

    # Detect package manager
    local pkg_type
    pkg_type=$(detect_package_manager)

    if [[ "$pkg_type" == "unknown" ]]; then
        error "Could not detect package manager (apt or yum/dnf required).

For macOS, use Homebrew instead:
  brew install nmelo/tap/bluectl nmelo/tap/km"
    fi

    # Validate architecture for requested packages BEFORE touching the system
    if [[ ${#packages[@]} -gt 0 ]]; then
        validate_packages "${packages[@]}"
    fi

    # Set up repository
    setup_repository "$pkg_type"

    # Install packages if any were specified
    if [[ ${#packages[@]} -gt 0 ]]; then
        install_packages "$pkg_type" "${packages[@]}"
        info "Installation complete."
    else
        info "Repository configured. Install packages with:"
        case "$pkg_type" in
            deb)
                echo "  sudo apt install bluectl km"
                ;;
            rpm)
                echo "  sudo yum install bluectl km"
                ;;
        esac
    fi
}

main "$@"
