# Version extraction utility for InterceptSuite on Windows
# Extracts version information from the .csproj file

param(
    [Parameter(Position=0)]
    [ValidateSet("version", "product-version", "title", "description", "company", "copyright")]
    [string]$Property = "version"
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CsprojFile = Join-Path $ScriptDir "..\..\InterceptSuite.csproj"

if (-not (Test-Path $CsprojFile)) {
    Write-Error "InterceptSuite.csproj not found at $CsprojFile"
    exit 1
}

# Load the XML content
[xml]$csproj = Get-Content $CsprojFile

function Get-PropertyValue {
    param($PropertyName, $DefaultValue = "")

    $value = $csproj.Project.PropertyGroup.$PropertyName
    if ($value) {
        return $value
    }
    return $DefaultValue
}

function Get-Version {
    $version = Get-PropertyValue "AssemblyVersion"
    if (-not $version) {
        $version = Get-PropertyValue "FileVersion"
    }
    if (-not $version) {
        $version = Get-PropertyValue "ProductVersion"
    }
    if (-not $version) {
        $version = "1.0.0.0"
    }
    return $version
}

function Get-ProductVersion {
    $version = Get-PropertyValue "ProductVersion"
    if (-not $version) {
        # Convert AssemblyVersion to ProductVersion (remove last .0 if present)
        $version = (Get-Version) -replace '\.0$', ''
    }
    return $version
}

switch ($Property) {
    "version" {
        Get-Version
    }
    "product-version" {
        Get-ProductVersion
    }
    "title" {
        Get-PropertyValue "AssemblyTitle" "InterceptSuite Standard"
    }
    "description" {
        Get-PropertyValue "AssemblyDescription" "Network Intercept and Analysis Tool - Standard Edition"
    }
    "company" {
        Get-PropertyValue "AssemblyCompany" "InterceptSuite"
    }
    "copyright" {
        Get-PropertyValue "AssemblyCopyright" "© 2025 InterceptSuite/AnoF-Cyber/Sourav Kalal"
    }
}
