#!/bin/bash

# Comprehensive installer script for InterceptSuite build dependencies
# This script installs all required tools: FUSE, AppImageTool, and other dependencies

set -e

echo "InterceptSuite Build Dependencies Installer"
echo "==========================================="

# Global variables
TEMP_DIR="/tmp/interceptsuite-installer-$$"
INSTALL_DIR="/usr/local/bin"
LOG_FILE="/tmp/interceptsuite-installer.log"

# Create temp directory
mkdir -p "$TEMP_DIR"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Error handling
cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

error_exit() {
    log "ERROR: $1"
    exit 1
}

# Check if running as root for system installations
check_sudo() {
    if ! sudo -n true 2>/dev/null; then
        log "This script requires sudo access for system package installation."
        log "Please enter your password when prompted."
    fi
}

# Detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
    else
        DISTRO="unknown"
    fi

    log "Detected distribution: $DISTRO $VERSION"
}

# Install FUSE
install_fuse() {
    log "Installing FUSE..."

    # Check if FUSE is already installed
    if ldconfig -p | grep -q libfuse.so.2; then
        log "✓ FUSE is already installed"
        return 0
    fi

    case "$DISTRO" in
        ubuntu|debian)
            log "Installing FUSE on Ubuntu/Debian..."
            sudo apt-get update
            sudo apt-get install -y fuse libfuse2
            ;;
        fedora)
            log "Installing FUSE on Fedora..."
            sudo dnf install -y fuse-libs
            ;;
        rhel|centos|rocky|almalinux)
            if command -v dnf >/dev/null 2>&1; then
                log "Installing FUSE on RHEL/CentOS (dnf)..."
                sudo dnf install -y fuse-libs
            else
                log "Installing FUSE on RHEL/CentOS (yum)..."
                sudo yum install -y fuse-libs
            fi
            ;;
        opensuse*|suse*)
            log "Installing FUSE on openSUSE..."
            sudo zypper install -y fuse libfuse2
            ;;
        arch|manjaro)
            log "Installing FUSE on Arch Linux..."
            sudo pacman -S --noconfirm fuse2
            ;;
        *)
            error_exit "Unsupported distribution for automatic FUSE installation. Please install FUSE manually."
            ;;
    esac

    # Verify FUSE installation
    if ldconfig -p | grep -q libfuse.so.2; then
        log "✓ FUSE installed successfully"
        log "You may need to add your user to the 'fuse' group:"
        log "  sudo usermod -a -G fuse \$USER"
        log "  newgrp fuse"
    else
        error_exit "FUSE installation verification failed"
    fi
}

# Download and install AppImageTool
install_appimagetool() {
    log "Installing AppImageTool..."

    # Check if appimagetool is already available
    if command -v appimagetool >/dev/null 2>&1; then
        log "✓ AppImageTool is already installed"
        return 0
    fi

    # Try package manager first
    local pkg_installed=false

    case "$DISTRO" in
        ubuntu|debian)
            if sudo apt-get install -y appimagetool 2>/dev/null; then
                pkg_installed=true
                log "✓ AppImageTool installed via package manager"
            fi
            ;;
        fedora)
            if sudo dnf install -y appimagetool 2>/dev/null; then
                pkg_installed=true
                log "✓ AppImageTool installed via package manager"
            fi
            ;;
        arch|manjaro)
            if command -v yay >/dev/null 2>&1; then
                if yay -S --noconfirm appimagetool-bin 2>/dev/null; then
                    pkg_installed=true
                    log "✓ AppImageTool installed via AUR"
                fi
            fi
            ;;
    esac

    # If package manager installation failed, download from GitHub
    if [ "$pkg_installed" = false ]; then
        log "Downloading AppImageTool from GitHub..."

        cd "$TEMP_DIR"

        # Download AppImageTool from continuous release (handles 302 redirects automatically)
        local download_url="https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"

        if ! wget -q --show-progress "$download_url" -O appimagetool-x86_64.AppImage; then
            error_exit "Failed to download AppImageTool from GitHub"
        fi

        # Make it executable
        chmod +x appimagetool-x86_64.AppImage

        # Install to system directory
        log "Installing AppImageTool to $INSTALL_DIR..."
        sudo mv appimagetool-x86_64.AppImage "$INSTALL_DIR/appimagetool"

        # Verify installation
        if [ -x "$INSTALL_DIR/appimagetool" ]; then
            log "✓ AppImageTool installed successfully to $INSTALL_DIR/appimagetool"
        else
            error_exit "Failed to install AppImageTool"
        fi
    fi
}

# Install build dependencies
install_build_dependencies() {
    log "Installing build dependencies..."

    case "$DISTRO" in
        ubuntu|debian)
            log "Installing build dependencies on Ubuntu/Debian..."
            sudo apt-get update
            sudo apt-get install -y \
                build-essential \
                cmake \
                git \
                wget \
                curl \
                squashfs-tools \
                desktop-file-utils \
                dpkg-dev \
                fakeroot \
                rpm \
                patchelf \
                file \
                tar \
                gzip
            ;;
        fedora)
            log "Installing build dependencies on Fedora..."
            sudo dnf install -y \
                gcc \
                gcc-c++ \
                cmake \
                git \
                wget \
                curl \
                squashfs-tools \
                desktop-file-utils \
                rpm-build \
                dpkg \
                patchelf \
                file \
                tar \
                gzip
            ;;
        rhel|centos|rocky|almalinux)
            log "Installing build dependencies on RHEL/CentOS..."
            local pkg_manager="yum"
            if command -v dnf >/dev/null 2>&1; then
                pkg_manager="dnf"
            fi

            sudo $pkg_manager install -y \
                gcc \
                gcc-c++ \
                cmake \
                git \
                wget \
                curl \
                squashfs-tools \
                desktop-file-utils \
                rpm-build \
                patchelf \
                file \
                tar \
                gzip
            ;;
        opensuse*|suse*)
            log "Installing build dependencies on openSUSE..."
            sudo zypper install -y \
                gcc \
                gcc-c++ \
                cmake \
                git \
                wget \
                curl \
                squashfs-tools \
                desktop-file-utils \
                rpm-build \
                patchelf \
                file \
                tar \
                gzip
            ;;
        arch|manjaro)
            log "Installing build dependencies on Arch Linux..."
            sudo pacman -S --noconfirm \
                base-devel \
                cmake \
                git \
                wget \
                curl \
                squashfs-tools \
                desktop-file-utils \
                rpm-tools \
                patchelf \
                file \
                tar \
                gzip
            ;;
        *)
            log "Warning: Unsupported distribution for automatic dependency installation"
            log "Please install the following packages manually:"
            log "  - build-essential/base-devel, cmake, git, wget, curl"
            log "  - squashfs-tools, desktop-file-utils, rpm-build/rpm-tools"
            log "  - dpkg-dev/dpkg, patchelf, file, tar, gzip"
            ;;
    esac

    log "✓ Build dependencies installation completed"
}

# Install .NET SDK if not present
install_dotnet() {
    log "Checking .NET SDK..."

    if command -v dotnet >/dev/null 2>&1; then
        local dotnet_version=$(dotnet --version 2>/dev/null || echo "unknown")
        log "✓ .NET SDK is already installed (version: $dotnet_version)"
        return 0
    fi

    log "Installing .NET SDK..."

    case "$DISTRO" in
        ubuntu|debian)
            # Add Microsoft package repository
            wget https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb -O "$TEMP_DIR/packages-microsoft-prod.deb"
            sudo dpkg -i "$TEMP_DIR/packages-microsoft-prod.deb"
            sudo apt-get update
            sudo apt-get install -y dotnet-sdk-9.0
            ;;
        fedora)
            sudo dnf install -y dotnet-sdk-9.0
            ;;
        rhel|centos|rocky|almalinux)
            # Add Microsoft repository
            sudo rpm -Uvh https://packages.microsoft.com/config/rhel/8/packages-microsoft-prod.rpm
            if command -v dnf >/dev/null 2>&1; then
                sudo dnf install -y dotnet-sdk-9.0
            else
                sudo yum install -y dotnet-sdk-9.0
            fi
            ;;
        opensuse*|suse*)
            sudo zypper install -y dotnet-sdk-9.0
            ;;
        arch|manjaro)
            sudo pacman -S --noconfirm dotnet-sdk
            ;;
        *)
            log "Warning: .NET SDK installation not automated for this distribution"
            log "Please install .NET 9.0 SDK manually from: https://dotnet.microsoft.com/download"
            ;;
    esac

    # Verify .NET installation
    if command -v dotnet >/dev/null 2>&1; then
        local dotnet_version=$(dotnet --version 2>/dev/null || echo "unknown")
        log "✓ .NET SDK installed successfully (version: $dotnet_version)"
    else
        log "Warning: .NET SDK installation could not be verified"
    fi
}

# Verify all installations
verify_installations() {
    log "Verifying installations..."

    local all_good=true

    # Check FUSE
    if ldconfig -p | grep -q libfuse.so.2; then
        log "✓ FUSE: OK"
    else
        log "✗ FUSE: MISSING"
        all_good=false
    fi

    # Check AppImageTool
    if command -v appimagetool >/dev/null 2>&1; then
        log "✓ AppImageTool: OK"
    else
        log "✗ AppImageTool: MISSING"
        all_good=false
    fi

    # Check essential build tools
    for tool in cmake git wget curl patchelf; do
        if command -v "$tool" >/dev/null 2>&1; then
            log "✓ $tool: OK"
        else
            log "✗ $tool: MISSING"
            all_good=false
        fi
    done

    # Check .NET
    if command -v dotnet >/dev/null 2>&1; then
        log "✓ .NET SDK: OK"
    else
        log "✗ .NET SDK: MISSING"
        all_good=false
    fi

    if [ "$all_good" = true ]; then
        log "✓ All dependencies are properly installed!"
        return 0
    else
        log "✗ Some dependencies are missing. Please check the log above."
        return 1
    fi
}

# Show usage information
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Install all required dependencies for building InterceptSuite packages.

OPTIONS:
    --fuse-only         Install only FUSE
    --appimage-only     Install only AppImageTool
    --build-deps-only   Install only build dependencies
    --dotnet-only       Install only .NET SDK
    --verify-only       Only verify existing installations
    --help, -h          Show this help message

Examples:
    $0                  # Install all dependencies
    $0 --fuse-only      # Install only FUSE
    $0 --verify-only    # Check what's already installed

EOF
}

# Main installation process
main() {
    log "Starting InterceptSuite dependencies installation..."

    # Parse command line arguments
    case "${1:-}" in
        --fuse-only)
            check_sudo
            detect_distro
            install_fuse
            ;;
        --appimage-only)
            check_sudo
            detect_distro
            install_appimagetool
            ;;
        --build-deps-only)
            check_sudo
            detect_distro
            install_build_dependencies
            ;;
        --dotnet-only)
            check_sudo
            detect_distro
            install_dotnet
            ;;
        --verify-only)
            verify_installations
            ;;
        --help|-h)
            show_usage
            exit 0
            ;;
        "")
            # Install everything
            check_sudo
            detect_distro
            install_fuse
            install_appimagetool
            install_build_dependencies
            install_dotnet
            verify_installations
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac

    log "Installation completed!"
    log "Log file available at: $LOG_FILE"

    # Show post-installation notes
    cat << EOF

Post-Installation Notes:
========================
1. If you installed FUSE, you may need to:
   - Add your user to the 'fuse' group: sudo usermod -a -G fuse \$USER
   - Log out and log back in, or run: newgrp fuse

2. AppImageTool is available as 'appimagetool' command

3. You can now build InterceptSuite packages using:
   ./build-packages.sh

4. Run '$0 --verify-only' to check all installations

EOF
}

# Run main function
main "$@"
