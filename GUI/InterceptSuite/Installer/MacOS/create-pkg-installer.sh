#!/bin/bash

# macOS PKG Installer Build Script for InterceptSuite Standard Edition
# Creates a .pkg installer from the .app bundle

set -e

# Configuration
PACKAGE_NAME="InterceptSuite Standard"
BUNDLE_ID="com.InterceptSuite.Standard"
INSTALLER_NAME="InterceptSuite Standard Installer"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

function print_header() {
    echo ""
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}$(printf '=%.0s' $(seq 1 ${#1}))${NC}"
}

function print_step() {
    echo ""
    echo -e "${YELLOW}$1${NC}"
}

function print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

function print_error() {
    echo -e "${RED}✗ $1${NC}"
}

function print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
INSTALLER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Source version information
source "$SCRIPT_DIR/../Linux/get-version.sh"

# Package information
PACKAGE_VERSION=$(get_product_version)

# Paths
BUILD_DIR="$SCRIPT_DIR/pkg-build"
UNIFIED_OUTPUT_DIR="$INSTALLER_DIR/dist"
APP_BUNDLE="$UNIFIED_OUTPUT_DIR/$PACKAGE_NAME.app"
PKG_ROOT="$BUILD_DIR/pkg-root"
PKG_RESOURCES="$BUILD_DIR/pkg-resources"
LICENSE_FILE="$PROJECT_ROOT/LICENSE"

function check_prerequisites() {
    print_step "Checking prerequisites..."

    local all_good=true

    # Check if we're on macOS
    if [[ "$OSTYPE" != "darwin"* ]]; then
        print_error "This script must be run on macOS"
        all_good=false
    fi

    # Check for required tools
    if command -v pkgbuild >/dev/null 2>&1; then
        print_success "pkgbuild found"
    else
        print_error "pkgbuild not found. Please install Xcode Command Line Tools"
        all_good=false
    fi

    if command -v productbuild >/dev/null 2>&1; then
        print_success "productbuild found"
    else
        print_error "productbuild not found. Please install Xcode Command Line Tools"
        all_good=false
    fi

    # Check if app bundle exists
    if [ -d "$APP_BUNDLE" ]; then
        print_success "App bundle found: $APP_BUNDLE"
    else
        print_error "App bundle not found: $APP_BUNDLE"
        print_error "Please run build-installer.sh first to create the .app bundle"
        all_good=false
    fi

    # Check if license file exists
    if [ -f "$LICENSE_FILE" ]; then
        print_success "License file found: $LICENSE_FILE"
    else
        print_error "License file not found: $LICENSE_FILE"
        all_good=false
    fi

    return $([ "$all_good" = true ])
}

function prepare_build_directory() {
    print_step "Preparing build directory..."

    # Clean and create build directory structure
    rm -rf "$BUILD_DIR"
    mkdir -p "$PKG_ROOT/Applications"
    mkdir -p "$PKG_RESOURCES"

    print_success "Build directory prepared"
}

function copy_app_bundle() {
    print_step "Copying app bundle to package root..."

    # Copy the app bundle to the package root
    cp -R "$APP_BUNDLE" "$PKG_ROOT/Applications/"

    # Verify the copy
    if [ -d "$PKG_ROOT/Applications/$PACKAGE_NAME.app" ]; then
        print_success "App bundle copied successfully"
    else
        print_error "Failed to copy app bundle"
        exit 1
    fi
}

function prepare_license() {
    print_step "Preparing license file..."

    # Copy license to resources directory
    cp "$LICENSE_FILE" "$PKG_RESOURCES/License.txt"

    # Create a Welcome.txt file
    cat > "$PKG_RESOURCES/Welcome.txt" << EOF
Welcome to $PACKAGE_NAME

This installer will install $PACKAGE_NAME version $PACKAGE_VERSION on your Mac.

$PACKAGE_NAME is a powerful network traffic interception and analysis tool designed for security professionals and developers.

Features:
• TLS/HTTPS traffic interception
• Real-time packet analysis
• Certificate management
• Cross-platform support

System Requirements:
• macOS 13.0 (Ventura) or later
• Apple Silicon (ARM64) Mac

Click Continue to proceed with the installation.
EOF

    # Create a ReadMe.txt file
    cat > "$PKG_RESOURCES/ReadMe.txt" << EOF
$PACKAGE_NAME Installation Instructions

After installation, you can find $PACKAGE_NAME in your Applications folder.

To run the application:
1. Open Finder
2. Navigate to Applications
3. Double-click on "$PACKAGE_NAME"

If you encounter any issues:
1. Make sure you're running macOS 13.0 or later
2. Ensure you have an Apple Silicon (ARM64) Mac
3. Check that you have administrator privileges

For support and documentation, visit: https://github.com/InterceptSuite

Thank you for using $PACKAGE_NAME!
EOF

    print_success "License and documentation files prepared"
}

function create_distribution_xml() {
    print_step "Creating distribution.xml..."

    cat > "$BUILD_DIR/distribution.xml" << EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
    <title>$INSTALLER_NAME</title>
    <organization>$BUNDLE_ID</organization>
    <domains enable_localSystem="true"/>
    <options customize="never" require-scripts="false" rootVolumeOnly="true" />

    <!-- Define documents displayed at various steps -->
    <welcome    file="Welcome.txt"    mime-type="text/plain" />
    <license    file="License.txt"    mime-type="text/plain" />
    <readme     file="ReadMe.txt"     mime-type="text/plain" />

    <!-- Define the package choice -->
    <pkg-ref id="$BUNDLE_ID" version="$PACKAGE_VERSION" auth="root">$PACKAGE_NAME-component.pkg</pkg-ref>

    <choices-outline>
        <line choice="default">
            <line choice="$BUNDLE_ID"/>
        </line>
    </choices-outline>

    <choice id="default"/>
    <choice id="$BUNDLE_ID" visible="false">
        <pkg-ref id="$BUNDLE_ID"/>
    </choice>

    <!-- Define the background -->
    <background file="background" mime-type="image/png" alignment="topleft" scaling="tofit"/>

    <!-- System requirements -->
    <installation-check script="pm_install_check();"/>
    <script>
    <![CDATA[
        function pm_install_check() {
            if(!(system.compareVersions(system.version.ProductVersion, '13.0') >= 0)) {
                my.result.title = 'Unable to install';
                my.result.message = 'This software requires macOS 13.0 (Ventura) or later.';
                my.result.type = 'Fatal';
                return false;
            }

            if(system.sysctl('hw.optional.arm64') != 1) {
                my.result.title = 'Unable to install';
                my.result.message = 'This software requires an Apple Silicon (ARM64) Mac.';
                my.result.type = 'Fatal';
                return false;
            }

            return true;
        }
    ]]>
    </script>
</installer-gui-script>
EOF

    print_success "Distribution.xml created"
}

function create_background_image() {
    print_step "Creating installer background image..."

    # Create a simple background image using built-in tools
    # This creates a gradient background with the app logo if available
    if command -v sips >/dev/null 2>&1; then
        # Create a simple 600x400 background
        # Try to use the app icon if it exists
        local icon_path="$APP_BUNDLE/Contents/Resources/InterceptSuite.icns"
        if [ -f "$icon_path" ]; then
            # Convert icon to PNG and resize for background
            sips -s format png "$icon_path" --out "$PKG_RESOURCES/background.png" --resampleWidth 128 >/dev/null 2>&1 || true
        fi

        # If we don't have an icon or conversion failed, create a simple colored background
        if [ ! -f "$PKG_RESOURCES/background.png" ]; then
            # Create a simple 600x400 blue gradient background
            cat > "$PKG_RESOURCES/create_bg.py" << 'EOF'
from PIL import Image, ImageDraw
import sys

# Create a 600x400 image with a gradient
width, height = 600, 400
image = Image.new('RGB', (width, height))
draw = ImageDraw.Draw(image)

# Create a simple gradient
for y in range(height):
    # Blue gradient from light to dark
    color_value = int(255 - (y / height) * 100)
    color = (color_value // 3, color_value // 2, color_value)
    draw.line([(0, y), (width, y)], fill=color)

# Save the image
image.save(sys.argv[1])
EOF

            if command -v python3 >/dev/null 2>&1; then
                python3 -c "
from PIL import Image, ImageDraw
width, height = 600, 400
image = Image.new('RGB', (width, height), (70, 130, 180))
image.save('$PKG_RESOURCES/background.png')
" 2>/dev/null || echo "Background creation skipped - PIL not available"
            fi
        fi
    fi

    # If we still don't have a background, that's ok - the installer will work without it
    if [ -f "$PKG_RESOURCES/background.png" ]; then
        print_success "Background image created"
    else
        print_warning "Background image not created (optional)"
    fi
}

function build_component_package() {
    print_step "Building component package..."

    local component_pkg="$BUILD_DIR/$PACKAGE_NAME-component.pkg"
    local component_plist="$BUILD_DIR/component.plist"

    # Create the component property list file
    cat > "$component_plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
    <dict>
        <key>BundleHasStrictIdentifier</key>
        <true/>
        <key>BundleIsRelocatable</key>
        <false/>
        <key>BundleIsVersionChecked</key>
        <true/>
        <key>BundleOverwriteAction</key>
        <string>upgrade</string>
        <key>RootRelativeBundlePath</key>
        <string>Applications/$PACKAGE_NAME.app</string>
    </dict>
</array>
</plist>
EOF

    # Build the component package
    pkgbuild \
        --root "$PKG_ROOT" \
        --component-plist "$component_plist" \
        --identifier "$BUNDLE_ID" \
        --version "$PACKAGE_VERSION" \
        --install-location "/" \
        "$component_pkg"

    if [ $? -eq 0 ]; then
        print_success "Component package built successfully"
    else
        print_error "Failed to build component package"
        exit 1
    fi

    echo "$component_pkg"
}

function build_final_installer() {
    print_step "Building final installer package..."

    local component_pkg="$1"
    local final_pkg="$UNIFIED_OUTPUT_DIR/$PACKAGE_NAME-$PACKAGE_VERSION-macOS-ARM64.pkg"

    # Build the final installer
    productbuild \
        --distribution "$BUILD_DIR/distribution.xml" \
        --resources "$PKG_RESOURCES" \
        --package-path "$BUILD_DIR" \
        "$final_pkg"

    if [ $? -eq 0 ]; then
        print_success "Final installer package built successfully"
        echo "$final_pkg"
    else
        print_error "Failed to build final installer package"
        exit 1
    fi
}

function verify_installer() {
    print_step "Verifying installer package..."

    local pkg_file="$1"

    # Check if the package was created
    if [ -f "$pkg_file" ]; then
        local size=$(du -sh "$pkg_file" | cut -f1)
        print_success "Installer package created: $(basename "$pkg_file") ($size)"

        # Verify package structure
        if pkgutil --check-signature "$pkg_file" >/dev/null 2>&1; then
            print_success "Package signature verification passed"
        else
            print_warning "Package is not signed (this is normal for development builds)"
        fi

        return 0
    else
        print_error "Installer package was not created"
        return 1
    fi
}

function display_summary() {
    print_header "PKG Installer Build Summary"

    print_success "$INSTALLER_NAME created successfully!"

    echo ""
    echo -e "${GREEN}Build Configuration:${NC}"
    echo -e "  Project: $PACKAGE_NAME"
    echo -e "  Version: $PACKAGE_VERSION"
    echo -e "  Bundle ID: $BUNDLE_ID"
    echo -e "  Target: macOS 13.0+ (ARM64)"

    echo ""
    echo -e "${GREEN}Output files in 'Installer/dist':${NC}"

    # List created files
    local pkg_file="$UNIFIED_OUTPUT_DIR/$PACKAGE_NAME-$PACKAGE_VERSION-macOS-ARM64.pkg"
    if [ -f "$pkg_file" ]; then
        local size=$(du -sh "$pkg_file" | cut -f1)
        echo -e "  📦 $(basename "$pkg_file") ($size)"
    fi

    echo ""
    echo -e "${CYAN}Installation details:${NC}"
    echo -e "  • Installs to: /Applications/$PACKAGE_NAME.app"
    echo -e "  • Requires: macOS 13.0+ and Apple Silicon Mac"
    echo -e "  • Includes: License agreement and welcome message"
    echo -e "  • Signed: No (development build)"

    echo ""
    echo -e "${GREEN}To install:${NC}"
    echo -e "  Double-click the .pkg file and follow the installer wizard"

    echo ""
    echo -e "${GREEN}PKG installer build completed successfully! 🎉${NC}"
}

# Main execution
print_header "$INSTALLER_NAME - PKG Builder"

# Display version information
print_step "Version Information"
echo -e "${GREEN}Product Version: $(get_product_version)${NC}"
echo -e "${GREEN}Assembly Version: $(get_version)${NC}"
echo -e "${GREEN}Product Title: $(get_assembly_title)${NC}"
echo -e "${GREEN}Company: $(get_assembly_company)${NC}"

# Check prerequisites
if ! check_prerequisites; then
    print_error "Prerequisites check failed. Please resolve the issues above."
    exit 1
fi

# Build steps
prepare_build_directory
copy_app_bundle
prepare_license
create_distribution_xml
create_background_image

# Build the packages
component_pkg=$(build_component_package)
final_pkg=$(build_final_installer "$component_pkg")

# Verify and display results
#if verify_installer "$final_pkg"; then
#    display_summary
#else
#    print_error "Installer verification failed"
#    exit 1
#fi

# Clean up temporary build files (optional)
print_step "Cleaning up temporary files..."
rm -rf "$BUILD_DIR"
print_success "Cleanup completed"
