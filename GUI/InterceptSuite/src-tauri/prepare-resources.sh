#!/bin/bash
# Pre-build script to prepare native libraries for Tauri bundling

set -e

# Get the directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
BUILD_DIR="$WORKSPACE_ROOT/build"
TAURI_DIR="$SCRIPT_DIR"

# Determine the build configuration
BUILD_CONFIG="${CARGO_PROFILE:-Release}"
if [ "$CARGO_PROFILE" = "dev" ]; then
    BUILD_CONFIG="Debug"
fi

echo "Preparing native libraries for bundling..."
echo "Workspace root: $WORKSPACE_ROOT"
echo "Build configuration: $BUILD_CONFIG"

# Create a resources directory in the Tauri project
RESOURCES_DIR="$TAURI_DIR/resources"
mkdir -p "$RESOURCES_DIR"


# Determine the platform
case "$(uname -s)" in
    CYGWIN*|MINGW*|MSYS*)
        PLATFORM="windows"
        ;;
    Linux*)
        PLATFORM="linux"
        ;;
    Darwin*)
        PLATFORM="macos"
        ;;
    *)
        echo "Unsupported platform: $(uname -s)"
        exit 1
        ;;
esac

echo "Detected platform: $PLATFORM"

# Copy the appropriate libraries based on the platform
case "$PLATFORM" in
    "windows")
        if [ -f "$BUILD_DIR/$BUILD_CONFIG/Intercept.dll" ]; then
            cp "$BUILD_DIR/$BUILD_CONFIG/Intercept.dll" "$RESOURCES_DIR/"
            echo "Copied Intercept.dll"
        else
            echo "Warning: Intercept.dll not found in $BUILD_DIR/$BUILD_CONFIG/"
        fi

        # Note: OpenSSL is now statically linked into Intercept.dll
        # No need to copy separate OpenSSL DLLs anymore
        ;;

    "linux")
        # Try both the config-specific path and the root build path
        if [ -f "$BUILD_DIR/$BUILD_CONFIG/libIntercept.so" ]; then
            cp "$BUILD_DIR/$BUILD_CONFIG/libIntercept.so" "$RESOURCES_DIR/"
            echo "Copied libIntercept.so from $BUILD_DIR/$BUILD_CONFIG/"
        elif [ -f "$BUILD_DIR/libIntercept.so" ]; then
            cp "$BUILD_DIR/libIntercept.so" "$RESOURCES_DIR/"
            echo "Copied libIntercept.so from $BUILD_DIR/"
        else
            echo "Warning: libIntercept.so not found in $BUILD_DIR/$BUILD_CONFIG/ or $BUILD_DIR/"
        fi

        # Note: OpenSSL is now statically linked into libIntercept.so
        # No need to copy separate OpenSSL libraries anymore


        ;;

    "macos")
        if [ -f "$BUILD_DIR/$BUILD_CONFIG/libIntercept.dylib" ]; then
            cp "$BUILD_DIR/$BUILD_CONFIG/libIntercept.dylib" "$RESOURCES_DIR/"
            echo "Copied libIntercept.dylib from $BUILD_DIR/$BUILD_CONFIG/"
        elif [ -f "$BUILD_DIR/libIntercept.dylib" ]; then
            cp "$BUILD_DIR/libIntercept.dylib" "$RESOURCES_DIR/"
            echo "Copied libIntercept.dylib from $BUILD_DIR/"
        else
            echo "Warning: libIntercept.dylib not found in $BUILD_DIR/$BUILD_CONFIG/ or $BUILD_DIR/"
            echo "Available files in build directory:"
            ls -la "$BUILD_DIR/" || echo "Build directory not found"
            if [ -d "$BUILD_DIR/$BUILD_CONFIG" ]; then
                echo "Available files in $BUILD_DIR/$BUILD_CONFIG/:"
                ls -la "$BUILD_DIR/$BUILD_CONFIG/"
            fi
        fi

        # Verify the dylib architecture
        if [ -f "$RESOURCES_DIR/libIntercept.dylib" ]; then
            echo "Verifying dylib architecture:"
            file "$RESOURCES_DIR/libIntercept.dylib"
            if file "$RESOURCES_DIR/libIntercept.dylib" | grep -q "arm64"; then
                echo "✅ Confirmed ARM64 architecture"
            else
                echo "⚠️  Warning: Expected ARM64 architecture not found"
            fi
        fi

        # Note: OpenSSL is now statically linked into libIntercept.dylib
        # No need to copy separate OpenSSL dylibs anymore
        ;;
esac

echo "Native library preparation completed."
echo "Resources directory contents:"
ls -la "$RESOURCES_DIR"
