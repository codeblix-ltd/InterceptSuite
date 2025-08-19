#!/bin/bash

# Quick version info display for InterceptSuite
# Shows current version information from .csproj

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/get-version.sh"

echo "InterceptSuite Version Information"
echo "=================================="
echo "Product Version:  $(get_product_version)"
echo "Assembly Version: $(get_version)"
echo "Title:           $(get_assembly_title)"
echo "Description:     $(get_assembly_description)"
echo "Company:         $(get_assembly_company)"
echo "Copyright:       $(get_assembly_copyright)"
echo ""
echo "Package Names:"
echo "  DEB: interceptsuite-standard_$(get_product_version)_amd64.deb"
echo "  RPM: interceptsuite-standard-$(get_product_version)-1.x86_64.rpm"
echo "  AppImage: InterceptSuite-$(get_product_version)-x86_64.AppImage"
