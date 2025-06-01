#!/bin/bash
# Build script for macOS

# Default build type
BUILD_TYPE="Release"

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
cmake -B build -S . \
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
    -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
    -DCMAKE_OSX_ARCHITECTURES="x86_64;arm64"  # Universal binary for Intel and Apple Silicon

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
echo "Output library can be found at: build/libIntercept.dylib"
