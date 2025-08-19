#!/bin/bash

# Create AppImage for InterceptSuite

# Check if being run standalone or sourced
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    # Running standalone - set up variables
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
    GUI_PROJECT="$PROJECT_ROOT/GUI/InterceptSuite"

    # Source version information
    source "$SCRIPT_DIR/get-version.sh"

    # Package information
    PACKAGE_NAME="interceptsuite-standard"
    PACKAGE_VERSION=$(get_product_version)
    TITLE="$(get_assembly_title)"
    DESCRIPTION="$(get_assembly_description)"

    # Build directories
    BUILD_DIR="$SCRIPT_DIR/build"
    APPIMAGE_DIR="$BUILD_DIR/appimage"

    # Find the .so file
    SO_FILE=""
    if [ -f "$PROJECT_ROOT/build/libIntercept.so" ]; then
        SO_FILE="$PROJECT_ROOT/build/libIntercept.so"
    elif [ -f "$PROJECT_ROOT/build/Release/libIntercept.so" ]; then
        SO_FILE="$PROJECT_ROOT/build/Release/libIntercept.so"
    else
        echo "Error: libIntercept.so not found in build directories"
        exit 1
    fi

    # Clean and create build directory
    rm -rf "$BUILD_DIR"
    mkdir -p "$APPIMAGE_DIR"

    echo "Building AppImage standalone..."
    echo "Project root: $PROJECT_ROOT"
    echo "Package version: $PACKAGE_VERSION"
    echo "Native library: $SO_FILE"
fi

# This script is sourced by build-packages.sh or run standalone
# Variables are inherited from the parent script or set above

echo "Creating AppImage structure..."

# Create AppDir structure
APPDIR="$APPIMAGE_DIR/InterceptSuite.AppDir"
mkdir -p "$APPDIR/usr/bin"
mkdir -p "$APPDIR/usr/lib/InterceptSuite Standard"
mkdir -p "$APPDIR/usr/share/applications"
mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"

# Copy executable directly
cp "$GUI_PROJECT/bin/Release/net9.0/linux-x64/publish/InterceptSuite" "$APPDIR/usr/bin/InterceptSuite"
chmod +x "$APPDIR/usr/bin/InterceptSuite"

# Check if patchelf is available (should be installed by main build script)
if ! command -v patchelf >/dev/null 2>&1; then
    echo "Warning: patchelf not found, attempting to install..."
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update && sudo apt-get install -y patchelf || true
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y patchelf || true
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y patchelf || true
    elif command -v apk >/dev/null 2>&1; then
        sudo apk add patchelf || true
    else
        echo "Warning: Could not install patchelf. RPATH will not be set."
    fi
fi

# Set RPATH if patchelf is available
if command -v patchelf >/dev/null 2>&1; then
    echo "Setting RPATH for InterceptSuite binary..."
    # Set RPATH to look for libraries only in InterceptSuite Standard directory
    if patchelf --set-rpath '$ORIGIN/../lib/InterceptSuite Standard' "$APPDIR/usr/bin/InterceptSuite"; then
        echo "RPATH set to:"
        patchelf --print-rpath "$APPDIR/usr/bin/InterceptSuite"
    else
        echo "Warning: Failed to set RPATH, but continuing anyway"
    fi
else
    echo "Warning: patchelf not available. RPATH cannot be set."
    echo "The application may need LD_LIBRARY_PATH to find libraries."
fi

# Create environment setup script that will run before the application
cat > "$APPDIR/usr/bin/env.sh" << 'EOF'
#!/bin/bash
export LD_LIBRARY_PATH="/usr/lib/InterceptSuite Standard:$LD_LIBRARY_PATH"
EOF
chmod +x "$APPDIR/usr/bin/env.sh"

# Copy native libraries only to InterceptSuite Standard directory
cp "$SO_FILE" "$APPDIR/usr/lib/InterceptSuite Standard/libIntercept.so"

# Copy SkiaSharp library if it exists (ignore if not found)
if [ -f "$GUI_PROJECT/bin/Release/net9.0/linux-x64/publish/libSkiaSharp.so" ]; then
    cp "$GUI_PROJECT/bin/Release/net9.0/linux-x64/publish/libSkiaSharp.so" "$APPDIR/usr/lib/InterceptSuite Standard/"
    echo "✓ Copied libSkiaSharp.so"
else
    echo "⚠ libSkiaSharp.so not found - skipping (may be embedded)"
fi

# Copy HarfBuzzSharp library if it exists (ignore if not found)
if [ -f "$GUI_PROJECT/bin/Release/net9.0/linux-x64/publish/libHarfBuzzSharp.so" ]; then
    cp "$GUI_PROJECT/bin/Release/net9.0/linux-x64/publish/libHarfBuzzSharp.so" "$APPDIR/usr/lib/InterceptSuite Standard/"
    echo "✓ Copied libHarfBuzzSharp.so"
else
    echo "⚠ libHarfBuzzSharp.so not found - skipping (may be embedded)"
fi

# Copy icon
ICON_COPIED=false
if [ -f "$GUI_PROJECT/logo.png" ]; then
    cp "$GUI_PROJECT/logo.png" "$APPDIR/usr/share/icons/hicolor/256x256/apps/interceptsuite.png"
    cp "$GUI_PROJECT/logo.png" "$APPDIR/interceptsuite.png"  # Root level for AppImage
    ICON_COPIED=true
elif [ -f "$PROJECT_ROOT/logo.png" ]; then
    cp "$PROJECT_ROOT/logo.png" "$APPDIR/usr/share/icons/hicolor/256x256/apps/interceptsuite.png"
    cp "$PROJECT_ROOT/logo.png" "$APPDIR/interceptsuite.png"  # Root level for AppImage
    ICON_COPIED=true
fi

# Create desktop file for AppImage
cat > "$APPDIR/interceptsuite.desktop" << EOF
[Desktop Entry]
Type=Application
Name=$TITLE
Comment=$DESCRIPTION (v$PACKAGE_VERSION)
Exec=InterceptSuite
Icon=interceptsuite
Terminal=false
Categories=Network;
StartupNotify=true
X-AppVersion=$PACKAGE_VERSION
EOF

# Also create in standard location
cp "$APPDIR/interceptsuite.desktop" "$APPDIR/usr/share/applications/"

# Create AppRun script (entry point for AppImage)
cat > "$APPDIR/AppRun" << 'EOF'
#!/bin/bash

# AppRun script for InterceptSuite AppImage

# Get the directory where this AppImage is mounted
APPDIR="$(dirname "$(readlink -f "${0}")")"

# Set library path to include our native library directory
# Note: RPATH should handle this, but we keep it as a fallback
export LD_LIBRARY_PATH="$APPDIR/usr/lib/InterceptSuite Standard:${LD_LIBRARY_PATH}"

# Set the native library search path for our ResourceManager
export INTERCEPT_LIB_PATH="$APPDIR/usr/lib/InterceptSuite Standard"

# Run the application
exec "$APPDIR/usr/bin/InterceptSuite" "$@"
EOF

chmod +x "$APPDIR/AppRun"

# Verify appimagetool is available (should be installed by main build script)
if ! command -v appimagetool >/dev/null 2>&1; then
    echo "Warning: appimagetool not found"
    echo "Please ensure the main build script has installed all dependencies"
    echo "Trying to continue anyway for debugging..."
    # Don't exit immediately, try to continue
fi

# Create the AppImage
echo "Building AppImage..."
cd "$APPIMAGE_DIR"

# First, try to find appimagetool
APPIMAGETOOL_CMD=""
if command -v appimagetool >/dev/null 2>&1; then
    APPIMAGETOOL_CMD="appimagetool"
elif [ -f "/usr/bin/appimagetool" ]; then
    APPIMAGETOOL_CMD="/usr/bin/appimagetool"
elif [ -f "/usr/local/bin/appimagetool" ]; then
    APPIMAGETOOL_CMD="/usr/local/bin/appimagetool"
else
    echo "appimagetool not found in system, downloading..."
    APPIMAGETOOL_CMD="$BUILD_DIR/appimagetool"

    # Download appimagetool if not present
    if [ ! -f "$APPIMAGETOOL_CMD" ]; then
        echo "Downloading AppImageTool from GitHub..."
        # Use the continuous release download URL (handles 302 redirects automatically)
        if ! wget -O "$APPIMAGETOOL_CMD" "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage" 2>/dev/null; then
            echo "Falling back to AppImageKit release 13..."
            if ! wget -O "$APPIMAGETOOL_CMD" "https://github.com/AppImage/AppImageKit/releases/download/13/appimagetool-x86_64.AppImage" 2>/dev/null; then
                echo "Falling back to AppImageKit continuous build..."
                if ! wget -O "$APPIMAGETOOL_CMD" "https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage" 2>/dev/null; then
                    echo "Error: Failed to download appimagetool"
                    echo "Please install manually or use the installer.sh script"
                    return 1
                fi
            fi
        fi
        chmod +x "$APPIMAGETOOL_CMD"
    fi
fi

echo "Using appimagetool: $APPIMAGETOOL_CMD"

# Try to create AppImage, handle FUSE issues
if ARCH=x86_64 "$APPIMAGETOOL_CMD" "$APPDIR" "InterceptSuite-Standard-${PACKAGE_VERSION}-x86_64.AppImage" 2>/dev/null; then
    echo "AppImage created successfully using FUSE"
elif ARCH=x86_64 "$APPIMAGETOOL_CMD" --appimage-extract-and-run "$APPDIR" "InterceptSuite-Standard-${PACKAGE_VERSION}-x86_64.AppImage" 2>/dev/null; then
    echo "AppImage created successfully without FUSE"
else
    echo "Warning: AppImage creation failed. Trying with verbose output..."
    echo "Attempting AppImage creation with verbose output..."
    if ARCH=x86_64 "$APPIMAGETOOL_CMD" --verbose "$APPDIR" "InterceptSuite-Standard-${PACKAGE_VERSION}-x86_64.AppImage"; then
        echo "AppImage created successfully with verbose mode"
    else
        echo "Error: AppImage creation failed completely"
        echo "This may be due to:"
        echo "  - Missing FUSE support (try: sudo modprobe fuse)"
        echo "  - Missing dependencies"
        echo "  - Permission issues"
        echo "AppDir structure created at: $APPDIR"
        return 1
    fi
fi

if [ -f "InterceptSuite-Standard-${PACKAGE_VERSION}-x86_64.AppImage" ]; then
    chmod +x "InterceptSuite-Standard-${PACKAGE_VERSION}-x86_64.AppImage"
    echo "AppImage created: InterceptSuite-Standard-${PACKAGE_VERSION}-x86_64.AppImage"
else
    echo "Error: AppImage creation failed"
    exit 1
fi
