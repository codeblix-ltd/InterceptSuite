#!/bin/bash

# Version extraction utility for InterceptSuite
# Extracts version information from the .csproj file

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CSPROJ_FILE="$SCRIPT_DIR/../../InterceptSuite.csproj"

if [ ! -f "$CSPROJ_FILE" ]; then
    echo "Error: InterceptSuite.csproj not found at $CSPROJ_FILE"
    exit 1
fi

# Extract version information from .csproj
get_version() {
    # Try AssemblyVersion first, then FileVersion, then ProductVersion
    local version=$(grep -E '<AssemblyVersion>' "$CSPROJ_FILE" | sed -E 's/.*<AssemblyVersion>([^<]+)<.*/\1/' | head -1)
    if [ -z "$version" ]; then
        version=$(grep -E '<FileVersion>' "$CSPROJ_FILE" | sed -E 's/.*<FileVersion>([^<]+)<.*/\1/' | head -1)
    fi
    if [ -z "$version" ]; then
        version=$(grep -E '<ProductVersion>' "$CSPROJ_FILE" | sed -E 's/.*<ProductVersion>([^<]+)<.*/\1/' | head -1)
    fi
    if [ -z "$version" ]; then
        version="1.0.0.0"
    fi
    echo "$version"
}

get_product_version() {
    local version=$(grep -E '<ProductVersion>' "$CSPROJ_FILE" | sed -E 's/.*<ProductVersion>([^<]+)<.*/\1/' | head -1)
    if [ -z "$version" ]; then
        # Convert AssemblyVersion to ProductVersion (remove last .0 if present)
        version=$(get_version | sed 's/\.0$//')
    fi
    echo "$version"
}

get_assembly_title() {
    local title=$(grep -E '<AssemblyTitle>' "$CSPROJ_FILE" | sed -E 's/.*<AssemblyTitle>([^<]+)<.*/\1/' | head -1)
    if [ -z "$title" ]; then
        title="InterceptSuite Standard"
    fi
    echo "$title"
}

get_assembly_description() {
    local desc=$(grep -E '<AssemblyDescription>' "$CSPROJ_FILE" | sed -E 's/.*<AssemblyDescription>([^<]+)<.*/\1/' | head -1)
    if [ -z "$desc" ]; then
        desc="Network Intercept and Analysis Tool - Standard Edition"
    fi
    echo "$desc"
}

get_assembly_company() {
    local company=$(grep -E '<AssemblyCompany>' "$CSPROJ_FILE" | sed -E 's/.*<AssemblyCompany>([^<]+)<.*/\1/' | head -1)
    if [ -z "$company" ]; then
        company="InterceptSuite"
    fi
    echo "$company"
}

get_assembly_copyright() {
    local copyright=$(grep -E '<AssemblyCopyright>' "$CSPROJ_FILE" | sed -E 's/.*<AssemblyCopyright>([^<]+)<.*/\1/' | head -1)
    if [ -z "$copyright" ]; then
        copyright="© 2025 InterceptSuite/AnoF-Cyber/Sourav Kalal"
    fi
    echo "$copyright"
}

# Export functions for sourcing
if [ "${BASH_SOURCE[0]}" != "${0}" ]; then
    # Script is being sourced
    export -f get_version
    export -f get_product_version
    export -f get_assembly_title
    export -f get_assembly_description
    export -f get_assembly_company
    export -f get_assembly_copyright
else
    # Script is being run directly
    case "${1:-version}" in
        "version")
            get_version
            ;;
        "product-version")
            get_product_version
            ;;
        "title")
            get_assembly_title
            ;;
        "description")
            get_assembly_description
            ;;
        "company")
            get_assembly_company
            ;;
        "copyright")
            get_assembly_copyright
            ;;
        *)
            echo "Usage: $0 [version|product-version|title|description|company|copyright]"
            echo "Default: version"
            exit 1
            ;;
    esac
fi
