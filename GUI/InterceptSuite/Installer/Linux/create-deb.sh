#!/bin/bash

# Create DEB package for InterceptSuite

# Set umask to ensure proper permissions
umask 022

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
    ARCHITECTURE="amd64"
    MAINTAINER="$(get_assembly_company) <support@support.com>"
    DESCRIPTION="$(get_assembly_description)"
    TITLE="$(get_assembly_title)"
    COPYRIGHT="$(get_assembly_copyright)"
    HOMEPAGE="https://github.com/InterceptSuite/InterceptSuite"

    # Build directories - use temp directory to avoid Windows filesystem permission issues
    if [ -d "/tmp" ] && [ -w "/tmp" ]; then
        BUILD_DIR="/tmp/interceptsuite-deb-build-$$"
    else
        BUILD_DIR="$SCRIPT_DIR/build"
    fi
    DEB_DIR="$BUILD_DIR/deb"

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
    mkdir -p "$DEB_DIR"

    echo "Building DEB package standalone..."
    echo "Project root: $PROJECT_ROOT"
    echo "Package version: $PACKAGE_VERSION"
    echo "Native library: $SO_FILE"
    echo "Build directory: $BUILD_DIR"
    echo "DEB directory: $DEB_DIR"
fi

# This script is sourced by build-packages.sh or run standalone
# Variables are inherited from the parent script or set above

# Set umask to ensure proper permissions
umask 022

echo "Creating DEB package structure..."

# Create DEB package structure in a location with proper Unix permissions
DEB_PACKAGE_DIR="$DEB_DIR/package"

# Clean and recreate to ensure fresh permissions
rm -rf "$DEB_PACKAGE_DIR"
mkdir -p "$DEB_PACKAGE_DIR/DEBIAN"
mkdir -p "$DEB_PACKAGE_DIR/usr/bin"
mkdir -p "$DEB_PACKAGE_DIR/usr/lib/InterceptSuite Standard"
mkdir -p "$DEB_PACKAGE_DIR/usr/share/applications"
mkdir -p "$DEB_PACKAGE_DIR/usr/share/pixmaps"
mkdir -p "$DEB_PACKAGE_DIR/usr/share/doc/$PACKAGE_NAME"

# Set correct permissions immediately after creation
chmod 755 "$DEB_PACKAGE_DIR/DEBIAN"
chmod 755 "$DEB_PACKAGE_DIR/usr"
chmod 755 "$DEB_PACKAGE_DIR/usr/bin"
chmod 755 "$DEB_PACKAGE_DIR/usr/lib"
chmod 755 "$DEB_PACKAGE_DIR/usr/lib/InterceptSuite Standard"
chmod 755 "$DEB_PACKAGE_DIR/usr/share"
chmod 755 "$DEB_PACKAGE_DIR/usr/share/applications"
chmod 755 "$DEB_PACKAGE_DIR/usr/share/pixmaps"
chmod 755 "$DEB_PACKAGE_DIR/usr/share/doc"
chmod 755 "$DEB_PACKAGE_DIR/usr/share/doc/$PACKAGE_NAME"

# Copy executable directly to /usr/bin/
cp "$GUI_PROJECT/bin/Release/net9.0/linux-x64/publish/InterceptSuite" "$DEB_PACKAGE_DIR/usr/bin/"
chmod 755 "$DEB_PACKAGE_DIR/usr/bin/InterceptSuite"

# Check for patchelf and set RPATH for the binary
if ! command -v patchelf >/dev/null 2>&1; then
    echo "Installing patchelf to set RPATH..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update && apt-get install -y patchelf || true
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y patchelf || true
    elif command -v yum >/dev/null 2>&1; then
        yum install -y patchelf || true
    elif command -v apk >/dev/null 2>&1; then
        apk add patchelf || true
    else
        echo "Warning: Could not install patchelf. RPATH will not be set."
    fi
fi

# Set RPATH if patchelf is available
if command -v patchelf >/dev/null 2>&1; then
    echo "Setting RPATH for InterceptSuite binary in DEB package..."
    # Set RPATH to look for libraries only in /usr/lib/InterceptSuite Standard
    patchelf --set-rpath '/usr/lib/InterceptSuite Standard' "$DEB_PACKAGE_DIR/usr/bin/InterceptSuite" || echo "Failed to set RPATH"
    echo "RPATH set to:"
    patchelf --print-rpath "$DEB_PACKAGE_DIR/usr/bin/InterceptSuite"
else
    echo "ERROR: patchelf not available. RPATH cannot be set."
    echo "The application may not be able to find its libraries without LD_LIBRARY_PATH."
    echo "Please install patchelf and try again."
    exit 1
fi

# Create library directory
mkdir -p "$DEB_PACKAGE_DIR/usr/lib/InterceptSuite Standard/"

# Copy libraries only to InterceptSuite Standard directory
cp "$SO_FILE" "$DEB_PACKAGE_DIR/usr/lib/InterceptSuite Standard/libIntercept.so"
chmod 644 "$DEB_PACKAGE_DIR/usr/lib/InterceptSuite Standard/libIntercept.so"

# Copy required .NET native libraries (if they exist)
if [ -f "$GUI_PROJECT/bin/Release/net9.0/linux-x64/publish/libSkiaSharp.so" ]; then
    cp "$GUI_PROJECT/bin/Release/net9.0/linux-x64/publish/libSkiaSharp.so" "$DEB_PACKAGE_DIR/usr/lib/InterceptSuite Standard/"
    chmod 755 "$DEB_PACKAGE_DIR/usr/lib/InterceptSuite Standard/libSkiaSharp.so"
    echo "✓ Copied libSkiaSharp.so"
else
    echo "⚠ libSkiaSharp.so not found - skipping (may be embedded)"
fi

if [ -f "$GUI_PROJECT/bin/Release/net9.0/linux-x64/publish/libHarfBuzzSharp.so" ]; then
    cp "$GUI_PROJECT/bin/Release/net9.0/linux-x64/publish/libHarfBuzzSharp.so" "$DEB_PACKAGE_DIR/usr/lib/InterceptSuite Standard/"
    chmod 755 "$DEB_PACKAGE_DIR/usr/lib/InterceptSuite Standard/libHarfBuzzSharp.so"
    echo "✓ Copied libHarfBuzzSharp.so"
else
    echo "⚠ libHarfBuzzSharp.so not found - skipping (may be embedded)"
fi

# Copy icon (if exists)
if [ -f "$GUI_PROJECT/logo.png" ]; then
    cp "$GUI_PROJECT/logo.png" "$DEB_PACKAGE_DIR/usr/share/pixmaps/interceptsuite.png"
    chmod 644 "$DEB_PACKAGE_DIR/usr/share/pixmaps/interceptsuite.png"
elif [ -f "$PROJECT_ROOT/logo.png" ]; then
    cp "$PROJECT_ROOT/logo.png" "$DEB_PACKAGE_DIR/usr/share/pixmaps/interceptsuite.png"
    chmod 644 "$DEB_PACKAGE_DIR/usr/share/pixmaps/interceptsuite.png"
fi

# Create desktop entry
cat > "$DEB_PACKAGE_DIR/usr/share/applications/interceptsuite.desktop" << EOF
[Desktop Entry]
Type=Application
Name=$TITLE
Comment=$DESCRIPTION (v$PACKAGE_VERSION)
Exec=/usr/bin/InterceptSuite
Icon=interceptsuite
Terminal=false
Categories=Network;
StartupNotify=true
X-AppVersion=$PACKAGE_VERSION
EOF
chmod 644 "$DEB_PACKAGE_DIR/usr/share/applications/interceptsuite.desktop"

# Create copyright file
cat > "$DEB_PACKAGE_DIR/usr/share/doc/$PACKAGE_NAME/copyright" << EOF
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: InterceptSuite Standard
Upstream-Contact: InterceptSuite
Source: $HOMEPAGE

Files: *
Copyright: 2025 InterceptSuite/AnoF-Cyber/Sourav Kalal
License: Custom
 See the included LICENSE file for details.
EOF
chmod 644 "$DEB_PACKAGE_DIR/usr/share/doc/$PACKAGE_NAME/copyright"

# Create changelog
cat > "$DEB_PACKAGE_DIR/usr/share/doc/$PACKAGE_NAME/changelog.Debian" << EOF
$PACKAGE_NAME ($PACKAGE_VERSION-1) unstable; urgency=medium

  * Initial release of InterceptSuite Standard
  * Network interception and analysis capabilities
  * Cross-platform support

 -- $MAINTAINER  $(date -R)
EOF
chmod 644 "$DEB_PACKAGE_DIR/usr/share/doc/$PACKAGE_NAME/changelog.Debian"

# Compress changelog
gzip -9 "$DEB_PACKAGE_DIR/usr/share/doc/$PACKAGE_NAME/changelog.Debian"
chmod 644 "$DEB_PACKAGE_DIR/usr/share/doc/$PACKAGE_NAME/changelog.Debian.gz"

# Create control file
INSTALLED_SIZE=$(du -sk "$DEB_PACKAGE_DIR" | cut -f1)
cat > "$DEB_PACKAGE_DIR/DEBIAN/control" << EOF
Package: $PACKAGE_NAME
Version: $PACKAGE_VERSION
Section: net
Priority: optional
Architecture: $ARCHITECTURE
Installed-Size: $INSTALLED_SIZE
Depends: libc6 (>= 2.31), libssl3 (>= 3.0.0)
Maintainer: $MAINTAINER
Description: $DESCRIPTION
 InterceptSuite Standard is a network interception and analysis tool
 designed for security professionals and network administrators.
 .
 Features:
  - Network traffic interception
  - SSL/TLS proxy capabilities
  - Real-time analysis
  - Cross-platform support
Homepage: $HOMEPAGE
EOF
chmod 644 "$DEB_PACKAGE_DIR/DEBIAN/control"

# Create postinst script
cat > "$DEB_PACKAGE_DIR/DEBIAN/postinst" << 'EOF'
#!/bin/bash
set -e

# Update desktop database
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database /usr/share/applications
fi

# No environment setup file needed - RPATH will handle library loading
# The binary is configured to find its libraries via RPATH
echo "# InterceptSuite Standard has been installed" > "/etc/profile.d/interceptsuite.sh"
chmod 644 "/etc/profile.d/interceptsuite.sh"

# Ensure the executable has correct permissions
chmod 755 "/usr/bin/InterceptSuite"

echo "InterceptSuite Standard has been installed successfully!"
echo "You can run it from the applications menu or by typing 'InterceptSuite' in the terminal."
echo "Note: You may need to log out and log back in for the environment settings to take effect."
EOF

# Create prerm script
cat > "$DEB_PACKAGE_DIR/DEBIAN/prerm" << 'EOF'
#!/bin/bash
set -e

# Remove the environment file
if [ -f "/etc/profile.d/interceptsuite.sh" ]; then
    rm -f "/etc/profile.d/interceptsuite.sh"
fi
EOF

# Make scripts executable
chmod +x "$DEB_PACKAGE_DIR/DEBIAN/postinst"
chmod +x "$DEB_PACKAGE_DIR/DEBIAN/prerm"

# Fix ALL permissions for DEB package - this is critical for dpkg-deb
echo "Setting correct permissions for DEB package..."
# Set all directories to 755
find "$DEB_PACKAGE_DIR" -type d -exec chmod 755 {} \;
# Set all files to 644
find "$DEB_PACKAGE_DIR" -type f -exec chmod 644 {} \;
# Make executable files executable
chmod 755 "$DEB_PACKAGE_DIR/usr/bin/InterceptSuite"
chmod 755 "$DEB_PACKAGE_DIR/DEBIAN/postinst"
chmod 755 "$DEB_PACKAGE_DIR/DEBIAN/prerm"

# Ensure DEBIAN directory has correct permissions (must be between 0755 and 0775)
chmod 755 "$DEB_PACKAGE_DIR/DEBIAN"

# Debug: Check actual permissions before building
echo "Checking DEBIAN directory permissions:"
ls -ld "$DEB_PACKAGE_DIR/DEBIAN"
echo "Checking control file permissions:"
ls -l "$DEB_PACKAGE_DIR/DEBIAN/control"

# Build the DEB package
echo "Building DEB package..."

# Verify permissions before building
echo "Final permission check:"
ls -la "$DEB_PACKAGE_DIR/DEBIAN" | head -2

# Change to a clean directory for building
cd "$DEB_DIR"
dpkg-deb --build package "${PACKAGE_NAME}_${PACKAGE_VERSION}_${ARCHITECTURE}.deb"

# Move the package to the original script directory if we used temp
if [[ "$BUILD_DIR" == "/tmp/"* ]] && [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    FINAL_OUTPUT="$SCRIPT_DIR/${PACKAGE_NAME}_${PACKAGE_VERSION}_${ARCHITECTURE}.deb"
    mv "${PACKAGE_NAME}_${PACKAGE_VERSION}_${ARCHITECTURE}.deb" "$FINAL_OUTPUT"
    echo "DEB package created: $FINAL_OUTPUT"

    # Clean up temp directory
    rm -rf "$BUILD_DIR"
else
    echo "DEB package created: ${PACKAGE_NAME}_${PACKAGE_VERSION}_${ARCHITECTURE}.deb"
fi
