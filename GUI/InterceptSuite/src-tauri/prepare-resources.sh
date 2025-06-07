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

        if [ -f "$BUILD_DIR/$BUILD_CONFIG/libcrypto-3-x64.dll" ]; then
            cp "$BUILD_DIR/$BUILD_CONFIG/libcrypto-3-x64.dll" "$RESOURCES_DIR/"
            echo "Copied libcrypto-3-x64.dll"
        else
            echo "Warning: libcrypto-3-x64.dll not found"
        fi

        if [ -f "$BUILD_DIR/$BUILD_CONFIG/libssl-3-x64.dll" ]; then
            cp "$BUILD_DIR/$BUILD_CONFIG/libssl-3-x64.dll" "$RESOURCES_DIR/"
            echo "Copied libssl-3-x64.dll"
        else
            echo "Warning: libssl-3-x64.dll not found"
        fi
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

        # Copy OpenSSL libraries if they exist
        for ssl_lib in libssl.so libcrypto.so libssl.so.3 libcrypto.so.3; do
            if [ -f "$BUILD_DIR/$BUILD_CONFIG/$ssl_lib" ]; then
                cp "$BUILD_DIR/$BUILD_CONFIG/$ssl_lib" "$RESOURCES_DIR/"
                echo "Copied $ssl_lib from $BUILD_DIR/$BUILD_CONFIG/"
            elif [ -f "$BUILD_DIR/$ssl_lib" ]; then
                cp "$BUILD_DIR/$ssl_lib" "$RESOURCES_DIR/"
                echo "Copied $ssl_lib from $BUILD_DIR/"
            fi
        done


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

        # Copy OpenSSL libraries
        for ssl_lib in libssl.dylib libcrypto.dylib; do
            if [ -f "$BUILD_DIR/$BUILD_CONFIG/$ssl_lib" ]; then
                cp "$BUILD_DIR/$BUILD_CONFIG/$ssl_lib" "$RESOURCES_DIR/"
                echo "Copied $ssl_lib"
            fi
        done
        ;;
esac

echo "Native library preparation completed."
echo "Resources directory contents:"
ls -la "$RESOURCES_DIR"
