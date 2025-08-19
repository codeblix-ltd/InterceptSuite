#!/bin/bash

# Create RPM package for InterceptSuite

# Check if RPM tools are available
check_rpm_tools() {
    if ! command -v rpmbuild >/dev/null 2>&1; then
        echo "Error: rpmbuild not found"
        echo "Install with: sudo apt install -y rpm rpmbuild (Debian/Ubuntu)"
        echo "          or: sudo dnf install -y rpm-build (Fedora)"
        echo "          or: sudo yum install -y rpm-build (RHEL/CentOS)"
        return 1
    fi

    if ! command -v tar >/dev/null 2>&1; then
        echo "Error: tar not found"
        return 1
    fi

    return 0
}





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
    MAINTAINER="$(get_assembly_company) <support@InterceptSuite.com>"
    DESCRIPTION="$(get_assembly_description)"
    TITLE="$(get_assembly_title)"
    COPYRIGHT="$(get_assembly_copyright)"
    HOMEPAGE="https://github.com/InterceptSuite/InterceptSuite"

    # Build directories - use temp directory to avoid Windows filesystem permission issues
    if [ -d "/tmp" ] && [ -w "/tmp" ]; then
        BUILD_DIR="/tmp/interceptsuite-rpm-build-$$"
    else
        BUILD_DIR="$SCRIPT_DIR/build"
    fi
    RPM_DIR="$BUILD_DIR/rpm"

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
    mkdir -p "$RPM_DIR"

    echo "Building RPM package standalone..."
    echo "Project root: $PROJECT_ROOT"
    echo "Package version: $PACKAGE_VERSION"
    echo "Native library: $SO_FILE"
    echo "Build directory: $BUILD_DIR"
    echo "RPM directory: $RPM_DIR"

    # Check if RPM tools are available
    if ! check_rpm_tools; then
        exit 0  # Exit gracefully if RPM tools not available
    fi
    echo "Native library: $SO_FILE"
    echo "Build directory: $BUILD_DIR"
    echo "RPM directory: $RPM_DIR"
fi

# This script is sourced by build-packages.sh or run standalone
# Variables are inherited from the parent script or set above

# Check if RPM tools are available when sourced
if [ "${BASH_SOURCE[0]}" != "${0}" ]; then
    if ! check_rpm_tools; then
        echo "Skipping RPM package creation - tools not available"
        return 0 2>/dev/null || exit 0  # return if sourced, exit if not
    fi
fi

echo "Creating RPM package structure..."

# Create RPM build environment
RPM_BUILD_ROOT="$RPM_DIR/rpmbuild"
mkdir -p "$RPM_BUILD_ROOT"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

# Create spec file
SPEC_FILE="$RPM_BUILD_ROOT/SPECS/$PACKAGE_NAME.spec"
cat > "$SPEC_FILE" << EOF
Name:           $PACKAGE_NAME
Version:        $PACKAGE_VERSION
Release:        0
Summary:        $DESCRIPTION
License:        Custom
URL:            $HOMEPAGE
Source0:        %{name}-%{version}.tar.gz
BuildArch:      x86_64

Requires:       glibc >= 2.31
Requires:       openssl >= 3.0.0

%description
InterceptSuite Standard is a network interception and analysis tool
designed for security professionals and network administrators.

Features:
- Network traffic interception
- SSL/TLS proxy capabilities
- Real-time analysis
- Cross-platform support

%prep
%setup -q

%build
# Nothing to build, binaries are pre-compiled

%install
rm -rf %{buildroot}

# Create directories
mkdir -p %{buildroot}/usr/bin
mkdir -p "%{buildroot}/usr/lib/InterceptSuite Standard"
mkdir -p %{buildroot}/usr/share/applications
mkdir -p %{buildroot}/usr/share/pixmaps
mkdir -p %{buildroot}/etc/profile.d

# Copy executable directly to /usr/bin
cp -p %{_builddir}/%{name}-%{version}/InterceptSuite "%{buildroot}/usr/bin/"
chmod 755 "%{buildroot}/usr/bin/InterceptSuite"

# Create only InterceptSuite Standard directory for libraries
mkdir -p "%{buildroot}/usr/lib/InterceptSuite Standard"
cp -p %{_builddir}/%{name}-%{version}/libIntercept.so "%{buildroot}/usr/lib/InterceptSuite Standard/"
chmod 755 "%{buildroot}/usr/lib/InterceptSuite Standard/libIntercept.so"

# Copy optional libraries if they exist
if [ -f "%{_builddir}/%{name}-%{version}/libSkiaSharp.so" ]; then
    cp -p %{_builddir}/%{name}-%{version}/libSkiaSharp.so "%{buildroot}/usr/lib/InterceptSuite Standard/"
    chmod 755 "%{buildroot}/usr/lib/InterceptSuite Standard/libSkiaSharp.so"
fi

if [ -f "%{_builddir}/%{name}-%{version}/libHarfBuzzSharp.so" ]; then
    cp -p %{_builddir}/%{name}-%{version}/libHarfBuzzSharp.so "%{buildroot}/usr/lib/InterceptSuite Standard/"
    chmod 755 "%{buildroot}/usr/lib/InterceptSuite Standard/libHarfBuzzSharp.so"
fi

# Create and install desktop file
cp -p %{_builddir}/%{name}-%{version}/interceptsuite.desktop "%{buildroot}/usr/share/applications/"
chmod 644 "%{buildroot}/usr/share/applications/interceptsuite.desktop"

# Install icon
cp -p %{_builddir}/%{name}-%{version}/interceptsuite.png "%{buildroot}/usr/share/pixmaps/"
chmod 644 "%{buildroot}/usr/share/pixmaps/interceptsuite.png"

# No environment setup file needed - RPATH will handle library loading
# The binary is configured to find its libraries via RPATH
echo "# InterceptSuite Standard has been installed" > "%{buildroot}/etc/profile.d/interceptsuite.sh"
chmod 644 "%{buildroot}/etc/profile.d/interceptsuite.sh"

%files
%attr(755, root, root) /usr/bin/InterceptSuite
%attr(755, root, root) %dir "/usr/lib/InterceptSuite Standard"
%attr(755, root, root) "/usr/lib/InterceptSuite Standard/libIntercept.so"
%attr(755, root, root) "/usr/lib/InterceptSuite Standard/libSkiaSharp.so"
%attr(755, root, root) "/usr/lib/InterceptSuite Standard/libHarfBuzzSharp.so"
%attr(644, root, root) /usr/share/applications/interceptsuite.desktop
%attr(644, root, root) /usr/share/pixmaps/interceptsuite.png
%attr(644, root, root) /etc/profile.d/interceptsuite.sh
%attr(755, root, root) "/usr/lib/InterceptSuite Standard/libIntercept.so"
%attr(755, root, root) "/usr/lib/InterceptSuite Standard/libSkiaSharp.so"
%attr(755, root, root) "/usr/lib/InterceptSuite Standard/libHarfBuzzSharp.so"
%attr(644, root, root) /usr/share/applications/interceptsuite.desktop
%attr(644, root, root) /usr/share/pixmaps/interceptsuite.png
%attr(644, root, root) /etc/profile.d/interceptsuite.sh

%post
# Update desktop database
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database /usr/share/applications
fi



# Ensure the executable has correct permissions
if [ -f "/usr/bin/InterceptSuite" ]; then
    chmod 755 "/usr/bin/InterceptSuite"
fi

echo "InterceptSuite Standard has been installed successfully!"
echo "You can run it from the applications menu or by typing 'InterceptSuite' in the terminal."
echo "Note: You may need to log out and log back in for the environment settings to take effect."

%preun
# Remove the environment file
if [ -f "/etc/profile.d/interceptsuite.sh" ]; then
    rm -f "/etc/profile.d/interceptsuite.sh"
fi

%changelog
* $(date '+%a %b %d %Y') $MAINTAINER - $PACKAGE_VERSION-1
- Initial release of InterceptSuite Standard
- Network interception and analysis capabilities
- Cross-platform support
EOF

# Create source tarball
echo "Creating source tarball for RPM..."
SOURCE_DIR="$RPM_BUILD_ROOT/SOURCES/$PACKAGE_NAME-$PACKAGE_VERSION"
mkdir -p "$SOURCE_DIR"

# Debug source directory
echo "Creating source directory: $SOURCE_DIR"
mkdir -p "$SOURCE_DIR"
echo "Checking for InterceptSuite executable..."
ls -la "$GUI_PROJECT/bin/Release/net9.0/linux-x64/publish/"

# Copy files to source directory with debug output
echo "Copying InterceptSuite executable to $SOURCE_DIR/"
cp -v "$GUI_PROJECT/bin/Release/net9.0/linux-x64/publish/InterceptSuite" "$SOURCE_DIR/" || {
    echo "Error: Failed to copy InterceptSuite executable"
    echo "Source: $GUI_PROJECT/bin/Release/net9.0/linux-x64/publish/InterceptSuite"
    echo "Destination: $SOURCE_DIR/"
    exit 1
}

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
    echo "Setting RPATH for InterceptSuite binary in RPM package..."
    # Set RPATH to look for libraries only in /usr/lib/InterceptSuite Standard
    patchelf --set-rpath '/usr/lib/InterceptSuite Standard' "$SOURCE_DIR/InterceptSuite" || echo "Failed to set RPATH"
    echo "RPATH set to:"
    patchelf --print-rpath "$SOURCE_DIR/InterceptSuite"
else
    echo "ERROR: patchelf not available. RPATH cannot be set."
    echo "The application may not be able to find its libraries without LD_LIBRARY_PATH."
    echo "Please install patchelf and try again."
    exit 1
fi

# No launcher script needed - using RPATH to load libraries directly
echo "Using RPATH to load libraries directly without a launcher script"

echo "Copying libIntercept.so to $SOURCE_DIR/libIntercept.so"
cp -v "$SO_FILE" "$SOURCE_DIR/libIntercept.so" || {
    echo "Error: Failed to copy libIntercept.so"
    echo "Source: $SO_FILE"
    echo "Destination: $SOURCE_DIR/libIntercept.so"
    exit 1
}

echo "Copying libSkiaSharp.so to $SOURCE_DIR/ (if it exists)"
if [ -f "$GUI_PROJECT/bin/Release/net9.0/linux-x64/publish/libSkiaSharp.so" ]; then
    cp -v "$GUI_PROJECT/bin/Release/net9.0/linux-x64/publish/libSkiaSharp.so" "$SOURCE_DIR/" || {
        echo "Error: Failed to copy libSkiaSharp.so"
        echo "Source: $GUI_PROJECT/bin/Release/net9.0/linux-x64/publish/libSkiaSharp.so"
        echo "Destination: $SOURCE_DIR/"
        exit 1
    }
    echo "✓ Copied libSkiaSharp.so"
    SKIA_FOUND=true
else
    echo "⚠ libSkiaSharp.so not found - skipping (may be embedded)"
    SKIA_FOUND=false
fi

echo "Copying libHarfBuzzSharp.so to $SOURCE_DIR/ (if it exists)"
if [ -f "$GUI_PROJECT/bin/Release/net9.0/linux-x64/publish/libHarfBuzzSharp.so" ]; then
    cp -v "$GUI_PROJECT/bin/Release/net9.0/linux-x64/publish/libHarfBuzzSharp.so" "$SOURCE_DIR/" || {
        echo "Error: Failed to copy libHarfBuzzSharp.so"
        echo "Source: $GUI_PROJECT/bin/Release/net9.0/linux-x64/publish/libHarfBuzzSharp.so"
        echo "Destination: $SOURCE_DIR/"
        exit 1
    }
    echo "✓ Copied libHarfBuzzSharp.so"
    HARFBUZZ_FOUND=true
else
    echo "⚠ libHarfBuzzSharp.so not found - skipping (may be embedded)"
    HARFBUZZ_FOUND=false
fi

# Now update the spec file %files section based on what we found
echo "Updating spec file %files section based on available libraries..."

# Remove the old %files section and everything after it
sed -i '/^%files/,$ d' "$SPEC_FILE"

# Add new %files section with conditional libraries
cat >> "$SPEC_FILE" << 'EOF'
%files
%attr(755, root, root) /usr/bin/InterceptSuite
%attr(755, root, root) %dir "/usr/lib/InterceptSuite Standard"
%attr(755, root, root) "/usr/lib/InterceptSuite Standard/libIntercept.so"
EOF

# Add optional libraries to %files if they exist
if [ "$SKIA_FOUND" = true ]; then
    cat >> "$SPEC_FILE" << 'EOF'
%attr(755, root, root) "/usr/lib/InterceptSuite Standard/libSkiaSharp.so"
EOF
fi

if [ "$HARFBUZZ_FOUND" = true ]; then
    cat >> "$SPEC_FILE" << 'EOF'
%attr(755, root, root) "/usr/lib/InterceptSuite Standard/libHarfBuzzSharp.so"
EOF
fi

# Add remaining files
cat >> "$SPEC_FILE" << EOF
%attr(644, root, root) /usr/share/applications/interceptsuite.desktop
%attr(644, root, root) /usr/share/pixmaps/interceptsuite.png
%attr(644, root, root) /etc/profile.d/interceptsuite.sh

%post
# Update desktop database
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database /usr/share/applications
fi

# Ensure the executable has correct permissions
if [ -f "/usr/bin/InterceptSuite" ]; then
    chmod 755 "/usr/bin/InterceptSuite"
fi

echo "InterceptSuite Standard has been installed successfully!"
echo "You can run it from the applications menu or by typing 'InterceptSuite' in the terminal."
echo "Note: You may need to log out and log back in for the environment settings to take effect."

%preun
# Remove the environment file
if [ -f "/etc/profile.d/interceptsuite.sh" ]; then
    rm -f "/etc/profile.d/interceptsuite.sh"
fi

%changelog
* $(date '+%a %b %d %Y') $MAINTAINER - $PACKAGE_VERSION-1
- Initial release of InterceptSuite Standard
- Network interception and analysis capabilities
- Cross-platform support
EOF

# Create desktop file in source that points directly to the binary
cat > "$SOURCE_DIR/interceptsuite.desktop" << EOF
[Desktop Entry]
Type=Application
Name=$TITLE
Comment=$DESCRIPTION (v$PACKAGE_VERSION)
Exec=/usr/bin/InterceptSuite
Icon=interceptsuite
Terminal=false
Categories=Network;Security;
StartupNotify=true
X-AppVersion=$PACKAGE_VERSION
EOF

# Copy icon if exists
if [ -f "$GUI_PROJECT/logo.png" ]; then
    cp "$GUI_PROJECT/logo.png" "$SOURCE_DIR/interceptsuite.png"
elif [ -f "$PROJECT_ROOT/logo.png" ]; then
    cp "$PROJECT_ROOT/logo.png" "$SOURCE_DIR/interceptsuite.png"
fi

# Verify files exist before creating tarball
echo "Verifying files in source directory before creating tarball:"
ls -la "$SOURCE_DIR/"

# Create tarball with verbose output
cd "$RPM_BUILD_ROOT/SOURCES"
echo "Creating tarball from $PACKAGE_NAME-$PACKAGE_VERSION"
tar -cvzf "$PACKAGE_NAME-$PACKAGE_VERSION.tar.gz" "$PACKAGE_NAME-$PACKAGE_VERSION"

# Check tarball contents
echo "Verifying tarball contents:"
tar -tvf "$PACKAGE_NAME-$PACKAGE_VERSION.tar.gz"

# Remove source directory after tarball creation
rm -rf "$PACKAGE_NAME-$PACKAGE_VERSION"

# Build RPM
echo "Building RPM package..."
cd "$RPM_BUILD_ROOT"
rpmbuild --define "_topdir $RPM_BUILD_ROOT" -ba "SPECS/$PACKAGE_NAME.spec"

# Handle built RPM - this fixes the duplicate RPM issue
if [ -f "$RPM_BUILD_ROOT/RPMS/x86_64/$PACKAGE_NAME-$PACKAGE_VERSION-0.x86_64.rpm" ]; then
    # Determine final output location and filename
    if [[ "$BUILD_DIR" == "/tmp/"* ]] && [ "${BASH_SOURCE[0]}" = "${0}" ]; then
        # If running standalone, use the script directory
        FINAL_OUTPUT="$SCRIPT_DIR/$PACKAGE_NAME-$PACKAGE_VERSION.x86_64.rpm"
        mv "$RPM_BUILD_ROOT/RPMS/x86_64/$PACKAGE_NAME-$PACKAGE_VERSION-0.x86_64.rpm" "$FINAL_OUTPUT"
        echo "RPM package created: $FINAL_OUTPUT"

        # Clean up temp directory
        rm -rf "$BUILD_DIR"
    else
        # When sourced from build-packages.sh, put it in the UNIFIED_OUTPUT_DIR if defined
        if [ -n "$UNIFIED_OUTPUT_DIR" ] && [ -d "$UNIFIED_OUTPUT_DIR" ]; then
            # Move directly to unified output directory with consistent naming
            mv "$RPM_BUILD_ROOT/RPMS/x86_64/$PACKAGE_NAME-$PACKAGE_VERSION-0.x86_64.rpm" "$UNIFIED_OUTPUT_DIR/$PACKAGE_NAME-$PACKAGE_VERSION.x86_64.rpm"
            echo "RPM package created: $UNIFIED_OUTPUT_DIR/$PACKAGE_NAME-$PACKAGE_VERSION.x86_64.rpm"
        else
            # Fall back to the RPM_DIR if UNIFIED_OUTPUT_DIR is not available
            mv "$RPM_BUILD_ROOT/RPMS/x86_64/$PACKAGE_NAME-$PACKAGE_VERSION-0.x86_64.rpm" "$RPM_DIR/$PACKAGE_NAME-$PACKAGE_VERSION.x86_64.rpm"
            echo "RPM package created: $RPM_DIR/$PACKAGE_NAME-$PACKAGE_VERSION.x86_64.rpm"
        fi
    fi
else
    echo "Error: RPM package not found after build"
    ls -la "$RPM_BUILD_ROOT/RPMS/x86_64/"
    exit 1
fi
