<#
.SYNOPSIS
Installation and setup script for Port Intelligence Analyzer

.DESCRIPTION
This script sets up the Port Intelligence Analyzer module and verifies the installation.
Run this after downloading or cloning the repository.
#>

[CmdletBinding()]
param(
    [switch]$SkipTest,
    [switch]$AddToProfile,
    [string]$InstallPath
)

$ErrorActionPreference = "Stop"

Write-Host @"
╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║            PORT INTELLIGENCE ANALYZER - INSTALLATION                       ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Host ""

# Check PowerShell version
Write-Host "[1/7] Checking PowerShell version..." -ForegroundColor Yellow
$psVersion = $PSVersionTable.PSVersion
Write-Host "      PowerShell version: $($psVersion.Major).$($psVersion.Minor)" -ForegroundColor White

if ($psVersion.Major -lt 5) {
    Write-Host "      ✗ PowerShell 5.1 or higher is required!" -ForegroundColor Red
    exit 1
}
Write-Host "      ✓ PowerShell version compatible" -ForegroundColor Green
Write-Host ""

# Check administrator privileges
Write-Host "[2/7] Checking privileges..." -ForegroundColor Yellow
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    Write-Host "      [OK] Running as Administrator" -ForegroundColor Green
}
else {
    Write-Host "      [WARN] Not running as Administrator" -ForegroundColor Yellow
    Write-Host "      Some features will require admin privileges" -ForegroundColor Yellow
}
Write-Host ""

# Verify module files
Write-Host "[3/7] Verifying module files..." -ForegroundColor Yellow
$modulePath = $PSScriptRoot
$requiredFiles = @(
    "PortIntelligenceAnalyzer.psd1",
    "PortIntelligenceAnalyzer.psm1",
    "Private\Helpers.ps1",
    "Private\PortDatabase.ps1",
    "Public\Get-PortIntelligence.ps1",
    "Public\Get-PortServiceMapping.ps1",
    "Public\Get-PortRiskAssessment.ps1",
    "Public\Export-PortReport.ps1",
    "Public\Watch-PortChanges.ps1",
    "Public\Close-SuspiciousPort.ps1"
)

$missingFiles = @()
foreach ($file in $requiredFiles) {
    $fullPath = Join-Path $modulePath $file
    if (Test-Path $fullPath) {
        Write-Host "      ✓ $file" -ForegroundColor Green
    }
    else {
        Write-Host "      ✗ $file (missing)" -ForegroundColor Red
        $missingFiles += $file
    }
}

if ($missingFiles.Count -gt 0) {
    Write-Host ""
    Write-Host "      Error: Missing required files. Please ensure all files are present." -ForegroundColor Red
    exit 1
}
Write-Host ""

# Test module import
Write-Host "[4/7] Testing module import..." -ForegroundColor Yellow
try {
    Import-Module "$modulePath\PortIntelligenceAnalyzer.psd1" -Force -ErrorAction Stop
    Write-Host "      ✓ Module imported successfully" -ForegroundColor Green
}
catch {
    Write-Host "      ✗ Failed to import module: $_" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Verify exported functions
Write-Host "[5/7] Verifying exported functions..." -ForegroundColor Yellow
$expectedFunctions = @(
    "Get-PortIntelligence",
    "Get-PortServiceMapping", 
    "Get-PortRiskAssessment",
    "Export-PortReport",
    "Watch-PortChanges",
    "Close-SuspiciousPort"
)

$moduleInfo = Get-Module PortIntelligenceAnalyzer
$exportedFunctions = $moduleInfo.ExportedFunctions.Keys

foreach ($func in $expectedFunctions) {
    if ($exportedFunctions -contains $func) {
        Write-Host "      ✓ $func" -ForegroundColor Green
    }
    else {
        Write-Host "      ✗ $func (not exported)" -ForegroundColor Red
    }
}
Write-Host ""

# Quick functionality test
if (-not $SkipTest) {
    Write-Host "[6/7] Running quick functionality test..." -ForegroundColor Yellow
    try {
        Write-Host "      Testing Get-PortIntelligence..." -ForegroundColor White
        $testResult = Get-PortIntelligence | Select-Object -First 1
        
        if ($testResult) {
            Write-Host "      ✓ Successfully collected port data" -ForegroundColor Green
            Write-Host "        Sample: Port $($testResult.LocalPort) - $($testResult.ProcessName)" -ForegroundColor Gray
        }
        else {
            Write-Host "      ⚠️  No ports found (this may be normal)" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "      ✗ Test failed: $_" -ForegroundColor Red
    }
}
else {
    Write-Host "[6/7] Skipping functionality test..." -ForegroundColor Gray
}
Write-Host ""

# Add to PowerShell profile (optional)
Write-Host "[7/7] PowerShell profile integration..." -ForegroundColor Yellow
if ($AddToProfile) {
    try {
        $profilePath = $PROFILE.CurrentUserAllHosts
        $importStatement = "Import-Module '$modulePath\PortIntelligenceAnalyzer.psd1'"
        
        if (-not (Test-Path $profilePath)) {
            New-Item -Path $profilePath -ItemType File -Force | Out-Null
        }
        
        $profileContent = Get-Content $profilePath -Raw -ErrorAction SilentlyContinue
        if ($profileContent -notlike "*PortIntelligenceAnalyzer*") {
            Add-Content -Path $profilePath -Value "`n# Port Intelligence Analyzer"
            Add-Content -Path $profilePath -Value $importStatement
            Write-Host "      ✓ Added to PowerShell profile" -ForegroundColor Green
            Write-Host "        Module will auto-load in new sessions" -ForegroundColor Gray
        }
        else {
            Write-Host "      ✓ Already in PowerShell profile" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "      ⚠️  Could not update profile: $_" -ForegroundColor Yellow
    }
}
else {
    Write-Host "      To auto-load module, run:" -ForegroundColor Gray
    Write-Host "      .\Install.ps1 -AddToProfile" -ForegroundColor Gray
}
Write-Host ""

# Installation complete
Write-Host @"
╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║                    ✓ INSTALLATION SUCCESSFUL                               ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Green

Write-Host ""
Write-Host "Module Location: $modulePath" -ForegroundColor Cyan
Write-Host ""
Write-Host "QUICK START COMMANDS:" -ForegroundColor Yellow
Write-Host ""
Write-Host "  # Run basic port scan" -ForegroundColor Gray
Write-Host "  Get-PortIntelligence | Export-PortReport -Format Console" -ForegroundColor White
Write-Host ""
Write-Host "  # Find high-risk ports" -ForegroundColor Gray
Write-Host "  Get-PortIntelligence -RiskLevel Critical,High" -ForegroundColor White
Write-Host ""
Write-Host "  # Generate HTML report" -ForegroundColor Gray
Write-Host "  Get-PortIntelligence | Export-PortReport -Format HTML -OutputPath '.\report.html' -OpenAfterExport" -ForegroundColor White
Write-Host ""
Write-Host "  # Run interactive test suite" -ForegroundColor Gray
Write-Host "  .\Test-PortIntelligence.ps1" -ForegroundColor White
Write-Host ""
Write-Host "  # Run security audit example" -ForegroundColor Gray
Write-Host "  .\Examples\SecurityAudit.ps1" -ForegroundColor White
Write-Host ""
Write-Host "DOCUMENTATION:" -ForegroundColor Yellow
Write-Host "  • README.md - Full documentation" -ForegroundColor White
Write-Host "  • QUICKSTART.md - Quick start guide with examples" -ForegroundColor White
Write-Host "  • Get-Help Get-PortIntelligence -Full" -ForegroundColor White
Write-Host ""

# Offer to run test suite
if (-not $SkipTest) {
    $runTests = Read-Host "Would you like to run the interactive test suite now? (Y/N)"
    if ($runTests -eq 'Y' -or $runTests -eq 'y') {
        Write-Host ""
        & "$modulePath\Test-PortIntelligence.ps1"
    }
}

Write-Host ""
Write-Host "Happy port analyzing!" -ForegroundColor Cyan
Write-Host ""
