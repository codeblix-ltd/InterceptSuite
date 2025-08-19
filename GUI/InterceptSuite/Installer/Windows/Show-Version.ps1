# Quick version info display for InterceptSuite
# Shows current version information from .csproj

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$GetVersionScript = Join-Path $ScriptDir "Get-Version.ps1"

if (-not (Test-Path $GetVersionScript)) {
    Write-Error "Get-Version.ps1 not found"
    exit 1
}

$productVersion = & $GetVersionScript "product-version"
$assemblyVersion = & $GetVersionScript "version"
$title = & $GetVersionScript "title"
$description = & $GetVersionScript "description"
$company = & $GetVersionScript "company"
$copyright = & $GetVersionScript "copyright"

Write-Host "InterceptSuite Version Information" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host "Product Version:  $productVersion" -ForegroundColor Green
Write-Host "Assembly Version: $assemblyVersion" -ForegroundColor Green
Write-Host "Title:           $title" -ForegroundColor Green
Write-Host "Description:     $description" -ForegroundColor Green
Write-Host "Company:         $company" -ForegroundColor Green
Write-Host "Copyright:       $copyright" -ForegroundColor Green
Write-Host ""
Write-Host "Package Names:" -ForegroundColor Yellow
Write-Host "  Windows: InterceptSuite-Standard-$productVersion-Setup.exe" -ForegroundColor White
