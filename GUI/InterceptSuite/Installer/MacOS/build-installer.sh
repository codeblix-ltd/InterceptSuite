#!/bin/bash

# macOS Installer Build Script for InterceptSuite Standard Edition
# Creates a .app bundle for macOS ARM64
# Place this script in GUI/InterceptSuite/Installer/macOS/ directory

set -e

# Configuration
CONFIGURATION="Release"
OUTPUT_DIR="../dist"  # Unified output directory
ARCHITECTURE="osx-arm64"  # ARM64 only for Apple Silicon

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
GUI_PROJECT="$PROJECT_ROOT/GUI/InterceptSuite"
INSTALLER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Source version information
source "$SCRIPT_DIR/../Linux/get-version.sh"

# Package information
PACKAGE_NAME="InterceptSuite Standard"
PACKAGE_VERSION=$(get_product_version)
BUNDLE_ID="com.InterceptSuite.Standard"
EXECUTABLE_NAME="InterceptSuite"
ICON_NAME="InterceptSuite.icns"

# Paths
BUILD_DIR="$SCRIPT_DIR/build"
UNIFIED_OUTPUT_DIR="$INSTALLER_DIR/dist"
APP_BUNDLE="$BUILD_DIR/$PACKAGE_NAME.app"
PUBLISH_DIR="$GUI_PROJECT/bin/Release/net9.0/$ARCHITECTURE/publish"

function check_prerequisites() {
    print_step "Checking prerequisites..."

    local all_good=true

    # Check .NET SDK
    if command -v dotnet >/dev/null 2>&1; then
        local dotnet_version=$(dotnet --version)
        print_success ".NET SDK version: $dotnet_version"

        if [[ $dotnet_version == 9.* ]]; then
            print_success ".NET 9.0 SDK detected"
        else
            print_warning ".NET 9.0 SDK recommended, found: $dotnet_version"
        fi
    else
        print_error ".NET SDK not found. Please install .NET 9.0 SDK"
        all_good=false
    fi

    # Check if we're on macOS
    if [[ "$OSTYPE" != "darwin"* ]]; then
        print_error "This script must be run on macOS"
        all_good=false
    fi

    # Check for macOS tools
    if command -v install_name_tool >/dev/null 2>&1; then
        print_success "install_name_tool found for library path fixing"
    else
        print_warning "install_name_tool not found. This is unusual for macOS."
        print_warning "Library paths may not be set correctly."
    fi

    if command -v otool >/dev/null 2>&1; then
        print_success "otool found for library inspection"
    else
        print_warning "otool not found. This is unusual for macOS."
        print_warning "Library inspection will be skipped."
    fi

    # Check native library
    local dylib_file=""
    if [ -f "$PROJECT_ROOT/build/libIntercept.dylib" ]; then
        dylib_file="$PROJECT_ROOT/build/libIntercept.dylib"
    elif [ -f "$PROJECT_ROOT/build/Release/libIntercept.dylib" ]; then
        dylib_file="$PROJECT_ROOT/build/Release/libIntercept.dylib"
    else
        print_error "libIntercept.dylib not found in build directories"
        print_error "Please build the native library first"
        all_good=false
    fi

    if [ -n "$dylib_file" ]; then
        print_success "Native library found: $dylib_file"
        DYLIB_FILE="$dylib_file"
    fi

    # Check project file
    if [ -f "$GUI_PROJECT/InterceptSuite.csproj" ]; then
        print_success "Project file found: $GUI_PROJECT/InterceptSuite.csproj"
    else
        print_error "Project file not found: $GUI_PROJECT/InterceptSuite.csproj"
        all_good=false
    fi

    return $([ "$all_good" = true ])
}

function create_info_plist() {
    local plist_file="$1"

    print_step "Creating Info.plist..."

    cat > "$plist_file" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIconFile</key>
    <string>$ICON_NAME</string>
    <key>CFBundleIdentifier</key>
    <string>$BUNDLE_ID</string>
    <key>CFBundleName</key>
    <string>$PACKAGE_NAME</string>
    <key>CFBundleDisplayName</key>
    <string>$PACKAGE_NAME</string>
    <key>CFBundleVersion</key>
    <string>$PACKAGE_VERSION</string>
    <key>CFBundleShortVersionString</key>
    <string>$PACKAGE_VERSION</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
    <key>CFBundleExecutable</key>
    <string>$EXECUTABLE_NAME</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>LSApplicationCategoryType</key>
    <string>public.app-category.developer-tools</string>
    <key>NSHumanReadableCopyright</key>
    <string>$(get_assembly_copyright)</string>
</dict>
</plist>
EOF

    print_success "Info.plist created"
}

function build_dotnet_app() {
    print_step "Building .NET application for macOS ARM64..."

    cd "$GUI_PROJECT"

    # Clean previous builds
    rm -rf "$PUBLISH_DIR"

    # Check if AOT is enabled
    if grep -q '<PublishAot>true</PublishAot>' "$GUI_PROJECT/InterceptSuite.csproj"; then
        print_step "Building with AOT compilation..."
        dotnet publish -r "$ARCHITECTURE" -c "$CONFIGURATION" \
            -p:UseAppHost=true \
            --self-contained true \
            --nologo
    else
        # Standard build without single file packaging (better for native library handling)
        dotnet publish -r "$ARCHITECTURE" -c "$CONFIGURATION" \
            -p:UseAppHost=true \
            --self-contained true \
            --nologo
    fi

    if [ $? -ne 0 ]; then
        print_error "Failed to build .NET application"
        exit 1
    fi

    print_success ".NET application built successfully for macOS ARM64"

    # Verify the executable was created
    if [ ! -f "$PUBLISH_DIR/$EXECUTABLE_NAME" ]; then
        print_error "Executable not found after build: $PUBLISH_DIR/$EXECUTABLE_NAME"
        exit 1
    fi

    print_success "Executable found: $PUBLISH_DIR/$EXECUTABLE_NAME"
}

function create_app_bundle() {
    print_step "Creating .app bundle structure..."

    # Clean and create app bundle structure
    rm -rf "$APP_BUNDLE"
    mkdir -p "$APP_BUNDLE/Contents/MacOS"
    mkdir -p "$APP_BUNDLE/Contents/Resources"
    mkdir -p "$APP_BUNDLE/Contents/Frameworks"

    print_success "App bundle directories created"

    # Create Info.plist
    create_info_plist "$APP_BUNDLE/Contents/Info.plist"

    # Copy the published application
    print_step "Copying application files..."

    # With single-file packaging, we should have fewer files
    cp -R "$PUBLISH_DIR"/* "$APP_BUNDLE/Contents/MacOS/"

    # Make sure the main executable is executable
    chmod +x "$APP_BUNDLE/Contents/MacOS/$EXECUTABLE_NAME"    # Count the files we actually got and list them for debugging
    dll_count=$(find "$APP_BUNDLE/Contents/MacOS" -name "*.dll" | wc -l)
    dylib_count=$(find "$APP_BUNDLE/Contents/MacOS" -name "*.dylib" | wc -l)
    
    print_success "Application copied - DLLs: $dll_count, dylibs: $dylib_count"
    
    if [ "$dylib_count" -gt 0 ]; then
        print_step "Found dylib files:"
        find "$APP_BUNDLE/Contents/MacOS" -name "*.dylib" -exec basename {} \; | head -10
    fi

    # Only move Python-related libraries if they exist as separate files
    print_step "Checking for external libraries to move to Frameworks..."

    # Libraries that should be in Frameworks for better isolation
    # Include Python.NET, Avalonia, and other framework libraries
    framework_libs="libpython libPython python clr Python.Runtime libHarfBuzz libAvalonia libSkia"

    # Check if there are any framework libraries to move
    framework_libs_found=false    # Check both DLLs and dylibs
    for file in "$APP_BUNDLE/Contents/MacOS"/*.dll "$APP_BUNDLE/Contents/MacOS"/*.dylib; do
        if [ -f "$file" ]; then
            file_name=$(basename "$file")
            is_framework_related=false
            
            # Check if this is a framework library that should be moved
            for framework_pattern in $framework_libs; do
                if [[ "$file_name" == *"$framework_pattern"* ]]; then
                    is_framework_related=true
                    framework_libs_found=true
                    print_step "Moving framework library to Frameworks: $file_name"
                    mv "$file" "$APP_BUNDLE/Contents/Frameworks/"
                    break
                fi
            done
        fi
    done

    if [ "$framework_libs_found" = false ]; then
        print_success "Single-file build - no separate framework libraries to move"
    fi

    # Copy our native library to Frameworks
    print_step "Copying native library to Frameworks..."
    cp "$DYLIB_FILE" "$APP_BUNDLE/Contents/Frameworks/"

    # Update library references
    print_step "Updating library references..."

    # Add rpath for Frameworks directory to main executable
    install_name_tool -add_rpath "@executable_path/../Frameworks" "$APP_BUNDLE/Contents/MacOS/$EXECUTABLE_NAME" 2>/dev/null || true

    # Only process libraries we actually moved to Frameworks
    frameworks_lib_count=$(find "$APP_BUNDLE/Contents/Frameworks" -name "*.dylib" | wc -l)
    if [ "$frameworks_lib_count" -gt 0 ]; then
        print_step "Processing $frameworks_lib_count libraries in Frameworks..."

        for dylib in "$APP_BUNDLE/Contents/Frameworks/"*.dylib; do
            if [ -f "$dylib" ]; then
                dylib_name=$(basename "$dylib")
                chmod +x "$dylib"
                print_step "Processing: $dylib_name"

                # Set library ID for our custom libraries (skip system libraries)
                if [[ ! "$dylib_name" == libSystem* ]] && [[ ! "$dylib_name" == libmscordaccore* ]]; then
                    print_step "  Setting library ID: @rpath/$dylib_name"
                    install_name_tool -id "@rpath/$dylib_name" "$dylib" 2>/dev/null || true
                fi
            fi
        done
    else
        print_step "No libraries in Frameworks directory to process"
    fi

    # Copy icon if it exists
    if [ -f "$GUI_PROJECT/icons/icon.icns" ]; then
        cp "$GUI_PROJECT/icons/icon.icns" "$APP_BUNDLE/Contents/Resources/$ICON_NAME"
        print_success "Icon copied from icons folder to app bundle"
    elif [ -f "$GUI_PROJECT/logo.icns" ]; then
        cp "$GUI_PROJECT/logo.icns" "$APP_BUNDLE/Contents/Resources/$ICON_NAME"
        print_success "Icon copied from logo.icns to app bundle"
    elif [ -f "$PROJECT_ROOT/logo.icns" ]; then
        cp "$PROJECT_ROOT/logo.icns" "$APP_BUNDLE/Contents/Resources/$ICON_NAME"
        print_success "Icon copied from project root to app bundle"
    else
        print_warning "Icon file not found. App will use default icon."
    fi

    # Clean up debug symbols to reduce package size
    print_step "Cleaning up debug symbols..."
    find "$APP_BUNDLE" -name "*.dSYM" -type d -exec rm -rf {} \; 2>/dev/null || true

    # Remove any .pdb files (Windows debug symbols)
    find "$APP_BUNDLE" -name "*.pdb" -type f -delete

    # Set executable permissions and fix ownership for .pkg installation compatibility
    chmod +x "$APP_BUNDLE/Contents/MacOS/$EXECUTABLE_NAME"
    
    # Set proper permissions for all libraries
    find "$APP_BUNDLE/Contents/MacOS" -name "*.dylib" -exec chmod 755 {} \;
    find "$APP_BUNDLE/Contents/Frameworks" -name "*.dylib" -exec chmod 755 {} \;
    
    # Ensure all directories have proper permissions
    find "$APP_BUNDLE" -type d -exec chmod 755 {} \;
    find "$APP_BUNDLE" -type f -exec chmod 644 {} \;
    chmod +x "$APP_BUNDLE/Contents/MacOS/$EXECUTABLE_NAME"

    print_success "App bundle created successfully with proper permissions for .pkg installation"
}

function copy_to_unified_output() {
    print_step "Copying files to unified output directory..."

    # Ensure unified output directory exists
    mkdir -p "$UNIFIED_OUTPUT_DIR"

    # Copy app bundle with simple name
    local app_name="$PACKAGE_NAME.app"
    rm -rf "$UNIFIED_OUTPUT_DIR/$app_name"
    cp -R "$APP_BUNDLE" "$UNIFIED_OUTPUT_DIR/$app_name"
    print_success "App bundle copied: $app_name"
}

function display_summary() {
    print_header "Build Summary"

    print_success "$PACKAGE_NAME macOS app bundle created successfully!"

    echo ""
    echo -e "${GREEN}Build Configuration:${NC}"
    echo -e "  Project: $PACKAGE_NAME"
    echo -e "  Version: $PACKAGE_VERSION"
    echo -e "  Architecture: $ARCHITECTURE"
    echo -e "  Signed: No (signing disabled)"

    echo ""
    echo -e "${GREEN}Output files in unified 'Installer/dist':${NC}"

    # List created files
    local app_name="$PACKAGE_NAME.app"
    if [ -d "$UNIFIED_OUTPUT_DIR/$app_name" ]; then
        local size=$(du -sh "$UNIFIED_OUTPUT_DIR/$app_name" | cut -f1)
        echo -e "  📱 $app_name ($size)"
    fi

    echo ""
    echo -e "${CYAN}Installation details:${NC}"
    echo -e "  Target: macOS 13.0+ (Ventura and later)"
    echo -e "  Architecture: ARM64 (Apple Silicon)"
    echo -e "  Bundle ID: $BUNDLE_ID"
    echo -e "  Signed: No (signing disabled)"

    echo ""
    echo -e "${GREEN}Build completed successfully! 🎉${NC}"
}

# Main execution
print_header "InterceptSuite Standard Edition - macOS .app Bundle Builder"

# Display version information
print_step "Version Information"
echo -e "${GREEN}Product Version: $(get_product_version)${NC}"
echo -e "${GREEN}Assembly Version: $(get_version)${NC}"
echo -e "${GREEN}Product Title: $(get_assembly_title)${NC}"
echo -e "${GREEN}Company: $(get_assembly_company)${NC}"

# Check prerequisites
if ! check_prerequisites; then
    print_error "Prerequisites check failed. Please install missing components."
    exit 1
fi

# Create build directory
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Create unified output directory
mkdir -p "$UNIFIED_OUTPUT_DIR"
print_success "Using unified output directory: $UNIFIED_OUTPUT_DIR"

# Build steps
build_dotnet_app
create_app_bundle
copy_to_unified_output

# Summary
display_summary
