#!/bin/bash

# Build script for InterceptSuite Linux packages (AppImage, DEB, and RPM)
# This script automatically installs dependencies and creates all Linux package formats

set -e

# Function to install dependencies based on the system
install_dependencies() {
    echo "Installing packaging dependencies..."

    # Check if our comprehensive installer exists and use it
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -f "$SCRIPT_DIR/installer.sh" ]; then
        echo "Using comprehensive installer script..."
        bash "$SCRIPT_DIR/installer.sh"
        return $?
    fi

    # Fallback to manual installation if installer.sh is not available
    echo "Fallback: Installing dependencies manually..."

    if command -v apt >/dev/null 2>&1; then
        # Debian/Ubuntu
        echo "Detected Debian/Ubuntu system, installing dependencies..."
        sudo apt update

        # Install core dependencies
        sudo apt install -y \
            libfuse2 \
            squashfs-tools \
            desktop-file-utils \
            dpkg-dev \
            fakeroot \
            rpm \
            patchelf \
            wget \
            curl

        # Try to install appimagetool from repositories, if not available, download it
        if ! sudo apt install -y appimagetool 2>/dev/null; then
            echo "Installing AppImageTool from GitHub..."
            install_appimagetool_from_github
        fi
    elif command -v dnf >/dev/null 2>&1; then
        # Fedora
        echo "Detected Fedora system, installing dependencies..."
        sudo dnf install -y \
            fuse-libs \
            squashfs-tools \
            desktop-file-utils \
            rpm-build \
            dpkg \
            patchelf \
            wget \
            curl

        # Try to install appimagetool, fallback to GitHub
        if ! sudo dnf install -y appimagetool 2>/dev/null; then
            echo "Installing AppImageTool from GitHub..."
            install_appimagetool_from_github
        fi
    elif command -v yum >/dev/null 2>&1; then
        # RHEL/CentOS
        echo "Detected RHEL/CentOS system, installing dependencies..."
        sudo yum install -y \
            fuse-libs \
            squashfs-tools \
            desktop-file-utils \
            rpm-build \
            patchelf \
            wget \
            curl
        # appimagetool may need to be installed manually on older systems
        echo "Installing AppImageTool from GitHub..."
        install_appimagetool_from_github
    elif command -v pacman >/dev/null 2>&1; then
        # Arch Linux
        echo "Detected Arch Linux system, installing dependencies..."
        sudo pacman -S --needed \
            fuse2 \
            squashfs-tools \
            desktop-file-utils \
            rpm-tools \
            patchelf \
            wget \
            curl
        # Install appimagetool from AUR if available, otherwise from GitHub
        if command -v yay >/dev/null 2>&1; then
            if ! yay -S --needed appimagetool-bin 2>/dev/null; then
                echo "Installing AppImageTool from GitHub..."
                install_appimagetool_from_github
            fi
        else
            echo "Installing AppImageTool from GitHub..."
            install_appimagetool_from_github
        fi
    else
        echo "Warning: Unsupported package manager. Please install the following packages manually:"
        echo "  - appimagetool, libfuse2/fuse-libs, squashfs-tools, desktop-file-utils"
        echo "  - rpm/rpm-build, dpkg/dpkg-dev, patchelf, wget, curl"
        echo "Installing AppImageTool from GitHub..."
        install_appimagetool_from_github
    fi

    echo "Dependencies installation completed."
}

# Function to install AppImageTool from GitHub
install_appimagetool_from_github() {
    echo "Downloading AppImageTool from GitHub..."

    local temp_dir="/tmp/appimagetool-install-$$"
    mkdir -p "$temp_dir"

    cd "$temp_dir"

    # Download AppImageTool from continuous release (handles 302 redirects automatically)
    if wget -q --show-progress "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage" -O appimagetool-x86_64.AppImage; then
        chmod +x appimagetool-x86_64.AppImage

        # Install to system directory
        sudo mv appimagetool-x86_64.AppImage /usr/local/bin/appimagetool

        echo "✓ AppImageTool installed successfully to /usr/local/bin/appimagetool"
    else
        echo "✗ Failed to download AppImageTool from GitHub"
        return 1
    fi

    # Clean up
    cd /
    rm -rf "$temp_dir"
}

# Function to check if all required tools are available
check_dependencies() {
    local missing_tools=()

    # Check for essential tools
    for tool in patchelf wget; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done

    # Check for .NET SDK
    if ! command -v dotnet >/dev/null 2>&1; then
        missing_tools+=("dotnet")
    else
        # Check .NET version
        local dotnet_version=$(dotnet --version 2>/dev/null | cut -d. -f1)
        if [ -z "$dotnet_version" ] || [ "$dotnet_version" -lt 8 ]; then
            echo "Warning: .NET 8.0 or higher is recommended (found: $(dotnet --version 2>/dev/null || echo 'unknown'))"
        fi
    fi

    # Check for packaging tools (at least one should be available)
    local packaging_tools_available=false
    if command -v appimagetool >/dev/null 2>&1; then
        packaging_tools_available=true
    fi
    if command -v dpkg-deb >/dev/null 2>&1; then
        packaging_tools_available=true
    fi
    if command -v rpmbuild >/dev/null 2>&1; then
        packaging_tools_available=true
    fi

    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo "Missing required tools: ${missing_tools[*]}"
        return 1
    fi

    if [ "$packaging_tools_available" = false ]; then
        echo "No packaging tools available (appimagetool, dpkg-deb, rpmbuild)"
        return 1
    fi

    return 0
}

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
GUI_PROJECT="$PROJECT_ROOT/GUI/InterceptSuite"
INSTALLER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"  # GUI/InterceptSuite/Installer

# Source version information from .csproj
source "$SCRIPT_DIR/get-version.sh"

# Package information (extracted from .csproj)
PACKAGE_NAME="interceptsuite-standard"
PACKAGE_VERSION=$(get_product_version)
ASSEMBLY_VERSION=$(get_version)
ARCHITECTURE="amd64"
MAINTAINER="$(get_assembly_company) <contact@InterceptSuite.com>"
DESCRIPTION="$(get_assembly_description)"
TITLE="$(get_assembly_title)"
COPYRIGHT="$(get_assembly_copyright)"
HOMEPAGE="https://github.com/InterceptSuite/InterceptSuite"

# Build directories - use temp directories for better performance and isolation
BUILD_BASE_DIR="/tmp/interceptsuite-build-$$"
BUILD_DIR="$BUILD_BASE_DIR/build"
APPIMAGE_DIR="$BUILD_DIR/appimage"
DEB_DIR="$BUILD_BASE_DIR/deb"
RPM_DIR="$BUILD_BASE_DIR/rpm"

# Unified output directory (same as Windows script)
UNIFIED_OUTPUT_DIR="$INSTALLER_DIR/dist"

echo "Building InterceptSuite Linux packages..."
echo "Project root: $PROJECT_ROOT"
echo "Package name: $PACKAGE_NAME"
echo "Package version: $PACKAGE_VERSION"
echo "Assembly version: $ASSEMBLY_VERSION"
echo "Title: $TITLE"
echo "Description: $DESCRIPTION"
echo ""

# Install dependencies if needed
if ! check_dependencies; then
    echo "Some dependencies are missing. Attempting to install..."
    install_dependencies

    # Check again after installation
    if ! check_dependencies; then
        echo "Error: Failed to install all required dependencies."
        echo "Please install missing tools manually and try again."
        exit 1
    fi
fi

echo "All dependencies are available."
echo ""

# Clean any previous builds and setup directories
echo "Setting up build environment..."
rm -rf "$BUILD_BASE_DIR"
mkdir -p "$BUILD_DIR" "$APPIMAGE_DIR" "$DEB_DIR" "$RPM_DIR" "$UNIFIED_OUTPUT_DIR"

# Cleanup function to remove temp directories on exit
cleanup() {
    echo "Cleaning up temporary directories..."
    rm -rf "$BUILD_BASE_DIR"
}
trap cleanup EXIT

# Step 1: Locate the existing native library (.so file)
echo "Locating native library..."
SO_FILE=""
for potential_path in \
    "$PROJECT_ROOT/build/libIntercept.so" \
    "$PROJECT_ROOT/build/Release/libIntercept.so" \
    "$PROJECT_ROOT/libIntercept.so"; do
    if [ -f "$potential_path" ]; then
        SO_FILE="$potential_path"
        break
    fi
done

if [ -z "$SO_FILE" ]; then
    echo "Error: libIntercept.so not found in expected locations"
    echo "Looking for .so files in build directory:"
    find "$PROJECT_ROOT/build" -name "*.so" -type f 2>/dev/null || echo "No .so files found"
    echo "Please build the native library first using build_linux.sh"
    exit 1
fi

echo "Found native library: $SO_FILE"

# Step 2: Build the .NET application
echo "Building .NET application..."
cd "$GUI_PROJECT"

# Check if we need to restore packages
if [ ! -d "obj" ] || [ ! -f "obj/project.assets.json" ]; then
    echo "Restoring .NET packages..."
    dotnet restore --runtime linux-x64
fi

# Publish for Linux x64 with optimizations
echo "Publishing .NET application for Linux..."
dotnet publish -r linux-x64 -c Release --self-contained true

# Verify the executable was created
DOTNET_EXECUTABLE="$GUI_PROJECT/bin/Release/net9.0/linux-x64/publish/InterceptSuite"
if [ ! -f "$DOTNET_EXECUTABLE" ]; then
    echo "Error: InterceptSuite executable not found after build"
    echo "Expected location: $DOTNET_EXECUTABLE"
    ls -la "$GUI_PROJECT/bin/Release/net9.0/linux-x64/publish/" || true
    exit 1
fi

# Check executable permissions and size
chmod +x "$DOTNET_EXECUTABLE"
EXECUTABLE_SIZE=$(stat -f%z "$DOTNET_EXECUTABLE" 2>/dev/null || stat -c%s "$DOTNET_EXECUTABLE" 2>/dev/null || echo "unknown")
echo "✓ Executable created: $(basename "$DOTNET_EXECUTABLE") (${EXECUTABLE_SIZE} bytes)"

echo "Build completed successfully!"
echo ""

# Step 3: Create packages in parallel for better performance
echo "Creating packages..."

# Create packages sequentially for reliability
echo "Creating packages..."

# Initialize success flags
APPIMAGE_SUCCESS=false
DEB_SUCCESS=false
RPM_SUCCESS=false

# Create DEB package
if command -v dpkg-deb >/dev/null 2>&1; then
    echo "Creating DEB package..."
    if source "$SCRIPT_DIR/create-deb.sh" 2>/dev/null; then
        echo "✓ DEB package created successfully"
        DEB_SUCCESS=true
    else
        echo "✗ DEB package creation failed"
    fi
fi

# Create RPM package
if command -v rpmbuild >/dev/null 2>&1; then
    echo "Creating RPM package..."
    if source "$SCRIPT_DIR/create-rpm.sh" 2>/dev/null; then
        echo "✓ RPM package created successfully"
        RPM_SUCCESS=true
    else
        echo "✗ RPM package creation failed"
    fi
fi

# Create AppImage package
if command -v appimagetool >/dev/null 2>&1; then
    echo "Creating AppImage..."
    if source "$SCRIPT_DIR/create-appimage.sh" 2>/dev/null; then
        echo "✓ AppImage created successfully"
        APPIMAGE_SUCCESS=true
    else
        echo "✗ AppImage creation failed"
    fi
fi

echo ""
echo "Package creation completed!"
echo ""
echo "Collecting packages to unified output directory..."

# Simple package collection - just find and copy to dist folder
echo "Package Results:"

# Copy any packages found to the dist folder
echo "Collecting packages..."

# Find DEB packages
if [ "$DEB_SUCCESS" = true ]; then
    DEB_FILE=$(find "$SCRIPT_DIR" "$BUILD_BASE_DIR" -name "*.deb" -type f 2>/dev/null | head -1)
    if [ -n "$DEB_FILE" ]; then
        cp "$DEB_FILE" "$UNIFIED_OUTPUT_DIR/"
        echo "✓ DEB package: $(basename "$DEB_FILE")"
    else
        echo "✗ DEB package: Created but not found"
    fi
else
    echo "✗ DEB package: Failed to create"
fi

# Find RPM packages
if [ "$RPM_SUCCESS" = true ]; then
    # First try to find in the dist directory
    RPM_FILE=$(find "$UNIFIED_OUTPUT_DIR" -name "*.rpm" -type f 2>/dev/null | head -1)
    # If not found there, try the build directories
    if [ -z "$RPM_FILE" ]; then
        RPM_FILE=$(find "$BUILD_BASE_DIR" -name "*.rpm" -type f -path "*/RPMS/*" 2>/dev/null | head -1)
    fi
    if [ -n "$RPM_FILE" ]; then
        # Only copy if it's not already in the unified output dir
        if [[ "$RPM_FILE" != "$UNIFIED_OUTPUT_DIR"* ]]; then
            cp "$RPM_FILE" "$UNIFIED_OUTPUT_DIR/"
        fi
        echo "✓ RPM package: $(basename "$RPM_FILE")"
    else
        echo "✗ RPM package: Created but not found"
    fi
else
    echo "✗ RPM package: Failed to create"
fi

# Find AppImage packages
if [ "$APPIMAGE_SUCCESS" = true ]; then
    APPIMAGE_FILE=$(find "$APPIMAGE_DIR" "$BUILD_DIR" "$SCRIPT_DIR" -name "*.AppImage" -type f 2>/dev/null | head -1)
    if [ -n "$APPIMAGE_FILE" ]; then
        cp "$APPIMAGE_FILE" "$UNIFIED_OUTPUT_DIR/"
        echo "✓ AppImage: $(basename "$APPIMAGE_FILE")"
    else
        echo "✗ AppImage: Created but not found"
    fi
else
    echo "✗ AppImage: Failed to create"
fi

echo ""
echo "Final packages in dist folder:"
ls -lh "$UNIFIED_OUTPUT_DIR"/ 2>/dev/null || echo "  No files found"

# Count packages
TOTAL_PACKAGES=$(ls "$UNIFIED_OUTPUT_DIR"/*.{deb,rpm,AppImage} 2>/dev/null | wc -l)
echo ""
echo "Build Summary: $TOTAL_PACKAGES package(s) created successfully"

# Provide troubleshooting info if some packages failed
if [ "$APPIMAGE_SUCCESS" = false ] || [ "$DEB_SUCCESS" = false ] || [ "$RPM_SUCCESS" = false ]; then
    echo ""
    echo "Troubleshooting failed packages:"
    if [ "$APPIMAGE_SUCCESS" = false ]; then
        echo "  AppImage: Install dependencies with './installer.sh --appimage-only' or manually:"
        echo "           sudo apt install -y libfuse2 squashfs-tools"
        echo "           wget https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"
        echo "           chmod +x appimagetool-x86_64.AppImage && sudo mv appimagetool-x86_64.AppImage /usr/local/bin/appimagetool"
    fi
    [ "$DEB_SUCCESS" = false ] && echo "  DEB: Install with 'sudo apt install -y dpkg-dev fakeroot'"
    [ "$RPM_SUCCESS" = false ] && echo "  RPM: Install with 'sudo apt install -y rpm rpmbuild' or use Fedora/RHEL"
    echo ""
    echo "Or install all dependencies at once with: ./installer.sh"
fi
