#!/bin/bash
# Build script for Linux

# Default build type
BUILD_TYPE="Release"

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    elif command_exists lsb_release; then
        lsb_release -si | tr '[:upper:]' '[:lower:]'
    else
        echo "unknown"
    fi
}

# Check for required build tools
check_build_tools() {
    echo "Checking for required build tools..."

    local missing_tools=()

    if ! command_exists gcc && ! command_exists clang; then
        missing_tools+=("C compiler (gcc or clang)")
    fi

    if ! command_exists make; then
        missing_tools+=("make")
    fi

    if ! command_exists cmake; then
        missing_tools+=("cmake")
    fi

    if ! command_exists pkg-config; then
        missing_tools+=("pkg-config")
    fi

    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo "Error: Missing required build tools:"
        for tool in "${missing_tools[@]}"; do
            echo "  - $tool"
        done
        echo ""

        local distro=$(detect_distro)
        echo "To install these tools, run:"
        case "$distro" in
            ubuntu|debian)
                echo "  sudo apt update"
                echo "  sudo apt install build-essential cmake pkg-config"
                ;;
            centos|rhel|fedora)
                if command_exists dnf; then
                    echo "  sudo dnf groupinstall 'Development Tools'"
                    echo "  sudo dnf install cmake pkgconfig"
                else
                    echo "  sudo yum groupinstall 'Development Tools'"
                    echo "  sudo yum install cmake pkgconfig"
                fi
                ;;
            arch|manjaro)
                echo "  sudo pacman -S base-devel cmake pkgconf"
                ;;
            opensuse*)
                echo "  sudo zypper install -t pattern devel_basis"
                echo "  sudo zypper install cmake pkg-config"
                ;;
            *)
                echo "  Please install: build-essential, cmake, and pkg-config for your distribution"
                ;;
        esac
        echo ""
        return 1
    fi

    echo "All required build tools are available."
    return 0
}

# Check for required build tools
if ! check_build_tools; then
    exit 1
fi

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --debug)
            BUILD_TYPE="Debug"
            shift
            ;;
        --vcpkg-root=*)
            VCPKG_ROOT="${1#*=}"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check if VCPKG_ROOT is set
if [ -z "$VCPKG_ROOT" ] && [ -z "$VCPKG_INSTALLATION_ROOT" ]; then
    echo "Error: VCPKG_ROOT not specified and VCPKG_INSTALLATION_ROOT environment variable not set."
    echo "Please specify the vcpkg installation path using --vcpkg-root=/path/to/vcpkg"
    exit 1
fi

if [ -z "$VCPKG_ROOT" ]; then
    VCPKG_ROOT="$VCPKG_INSTALLATION_ROOT"
fi

# Ensure vcpkg exists
if [ ! -f "$VCPKG_ROOT/vcpkg" ]; then
    echo "vcpkg not found at $VCPKG_ROOT"
    echo "Please ensure vcpkg is installed and the path is correct."
    exit 1
fi

# Ensure vcpkg toolchain file exists
TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
if [ ! -f "$TOOLCHAIN_FILE" ]; then
    echo "vcpkg toolchain file not found at $TOOLCHAIN_FILE"
    echo "Please ensure vcpkg is properly installed."
    exit 1
fi

# Check if build directory exists, create it if not
if [ ! -d "build" ]; then
    mkdir build
fi

# Configure with CMake
echo "Configuring with CMake..."
echo "Build type: $BUILD_TYPE"
echo "vcpkg root: $VCPKG_ROOT"
echo "Toolchain file: $TOOLCHAIN_FILE"

cmake -B build -S . \
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
    -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
    -DVCPKG_INSTALLATION_ROOT="$VCPKG_ROOT" \
    -DCMAKE_VERBOSE_MAKEFILE=ON

if [ $? -ne 0 ]; then
    echo "CMake configuration failed."
    exit 1
fi

# Build
echo "Building..."
cmake --build build --config $BUILD_TYPE

if [ $? -ne 0 ]; then
    echo "Build failed."
    exit 1
fi

echo "Build completed successfully."
echo "Output library can be found at: build/libIntercept.so"
