# Example: Security Audit Script
# This script performs a comprehensive security audit of all open ports

# Import module
Import-Module "$PSScriptRoot\PortIntelligenceAnalyzer.psd1" -Force

Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║        PORT INTELLIGENCE SECURITY AUDIT SCRIPT                ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Create output directory
$outputDir = "$PSScriptRoot\SecurityAudit-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
Write-Host "[✓] Created output directory: $outputDir" -ForegroundColor Green
Write-Host ""

# Phase 1: Collect all port intelligence
Write-Host "[Phase 1] Collecting Port Intelligence..." -ForegroundColor Yellow
$allPorts = Get-PortIntelligence
Write-Host "  Found $($allPorts.Count) open ports" -ForegroundColor White
Write-Host ""

# Phase 2: Analyze risk distribution
Write-Host "[Phase 2] Analyzing Risk Distribution..." -ForegroundColor Yellow
$critical = @($allPorts | Where-Object {$_.Risk -eq 'Critical'})
$high = @($allPorts | Where-Object {$_.Risk -eq 'High'})
$medium = @($allPorts | Where-Object {$_.Risk -eq 'Medium'})
$low = @($allPorts | Where-Object {$_.Risk -eq 'Low'})
$unknown = @($allPorts | Where-Object {$_.Risk -eq 'Unknown'})

Write-Host "  🔴 Critical: $($critical.Count)" -ForegroundColor Red
Write-Host "  🟠 High: $($high.Count)" -ForegroundColor DarkRed
Write-Host "  🟡 Medium: $($medium.Count)" -ForegroundColor Yellow
Write-Host "  🟢 Low: $($low.Count)" -ForegroundColor Green
Write-Host "  ⚪ Unknown: $($unknown.Count)" -ForegroundColor Gray
Write-Host ""

# Phase 3: Identify critical issues
Write-Host "[Phase 3] Identifying Critical Issues..." -ForegroundColor Yellow

# Check for publicly exposed critical services
$exposedCritical = $allPorts | Where-Object {
    $_.Risk -in @('Critical', 'High') -and 
    $_.BindingScope -like "*Public*"
}

if ($exposedCritical) {
    Write-Host "  ⚠️  WARNING: $($exposedCritical.Count) high-risk services exposed to network!" -ForegroundColor Red
    foreach ($port in $exposedCritical) {
        Write-Host "     - Port $($port.LocalPort): $($port.PortName) ($($port.Risk))" -ForegroundColor Red
    }
}
else {
    Write-Host "  ✓ No critical services exposed to public network" -ForegroundColor Green
}
Write-Host ""

# Check for suspicious ports
$suspicious = $allPorts | Where-Object {$_.IsSuspicious}
if ($suspicious) {
    Write-Host "  ⚠️  ALERT: $($suspicious.Count) suspicious ports detected!" -ForegroundColor Magenta
    foreach ($port in $suspicious) {
        Write-Host "     - Port $($port.LocalPort): $($port.ProcessName) - $($port.RiskReason)" -ForegroundColor Magenta
    }
}
else {
    Write-Host "  ✓ No suspicious ports detected" -ForegroundColor Green
}
Write-Host ""

# Check for unsigned processes
$unsigned = $allPorts | Where-Object {
    $_.SignatureStatus -notin @('Valid', 'N/A') -and 
    $_.ProcessPath -ne 'Unknown'
}

if ($unsigned) {
    Write-Host "  ⚠️  WARNING: $($unsigned.Count) ports opened by unsigned/invalid executables!" -ForegroundColor Magenta
    foreach ($port in $unsigned) {
        Write-Host "     - Port $($port.LocalPort): $($port.ProcessName) ($($port.SignatureStatus))" -ForegroundColor Magenta
    }
}
else {
    Write-Host "  ✓ All processes properly signed" -ForegroundColor Green
}
Write-Host ""

# Phase 4: Category breakdown
Write-Host "[Phase 4] Service Category Analysis..." -ForegroundColor Yellow
$categories = $allPorts | Group-Object Category | Sort-Object Count -Descending

foreach ($cat in $categories) {
    Write-Host "  $($cat.Name): $($cat.Count) ports" -ForegroundColor White
}
Write-Host ""

# Phase 5: Generate recommendations
Write-Host "[Phase 5] Security Recommendations..." -ForegroundColor Yellow

$recommendations = @()

# RDP exposed?
$rdp = $allPorts | Where-Object {$_.LocalPort -eq 3389 -and $_.BindingScope -like "*Public*"}
if ($rdp) {
    $recommendations += "🔴 RDP (3389) is exposed to network. Enable NLA and use VPN."
}

# SMB exposed?
$smb = $allPorts | Where-Object {$_.LocalPort -in @(139, 445) -and $_.BindingScope -like "*Public*"}
if ($smb) {
    $recommendations += "🔴 SMB (445/139) is exposed. Disable if not needed or restrict to internal network."
}

# Database exposed?
$databases = $allPorts | Where-Object {
    $_.Category -eq "Database" -and $_.BindingScope -like "*Public*"
}
if ($databases) {
    $recommendations += "🟠 Database ports exposed to network. Bind to localhost or use VPN."
}

# Unencrypted protocols
$unencrypted = $allPorts | Where-Object {$_.LocalPort -in @(21, 23, 80, 25)}
if ($unencrypted) {
    $recommendations += "🟡 Unencrypted protocols detected (FTP/Telnet/HTTP). Use encrypted alternatives."
}

# Development ports in production?
$devPorts = $allPorts | Where-Object {$_.Category -eq "Development"}
if ($devPorts) {
    $recommendations += "🟡 Development ports open. Close when not actively developing."
}

if ($recommendations.Count -eq 0) {
    Write-Host "  ✓ No immediate security concerns identified!" -ForegroundColor Green
}
else {
    foreach ($rec in $recommendations) {
        Write-Host "  $rec" -ForegroundColor Yellow
    }
}
Write-Host ""

# Phase 6: Export reports
Write-Host "[Phase 6] Generating Reports..." -ForegroundColor Yellow

# Full report - all formats
$allPorts | Export-PortReport -Format HTML -OutputPath "$outputDir\Full-Report.html"
Write-Host "  ✓ HTML Report: $outputDir\Full-Report.html" -ForegroundColor Green

$allPorts | Export-PortReport -Format JSON -OutputPath "$outputDir\Full-Report.json"
Write-Host "  ✓ JSON Report: $outputDir\Full-Report.json" -ForegroundColor Green

$allPorts | Export-PortReport -Format CSV -OutputPath "$outputDir\Full-Report.csv"
Write-Host "  ✓ CSV Report: $outputDir\Full-Report.csv" -ForegroundColor Green

# High-risk ports only
if ($critical.Count -gt 0 -or $high.Count -gt 0) {
    $highRiskPorts = $allPorts | Where-Object {$_.Risk -in @('Critical', 'High')}
    $highRiskPorts | Export-PortReport -Format HTML -OutputPath "$outputDir\High-Risk-Ports.html"
    Write-Host "  ✓ High-Risk Report: $outputDir\High-Risk-Ports.html" -ForegroundColor Red
}

# Suspicious ports only
if ($suspicious.Count -gt 0) {
    $suspicious | Export-PortReport -Format HTML -OutputPath "$outputDir\Suspicious-Ports.html"
    Write-Host "  ✓ Suspicious Report: $outputDir\Suspicious-Ports.html" -ForegroundColor Magenta
}

Write-Host ""

# Phase 7: Summary
Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                    AUDIT SUMMARY                              ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "Total Ports Analyzed: $($allPorts.Count)" -ForegroundColor White
Write-Host "Critical Risk Ports: $($critical.Count)" -ForegroundColor $(if($critical.Count -gt 0){'Red'}else{'Green'})
Write-Host "High Risk Ports: $($high.Count)" -ForegroundColor $(if($high.Count -gt 0){'DarkRed'}else{'Green'})
Write-Host "Suspicious Ports: $($suspicious.Count)" -ForegroundColor $(if($suspicious.Count -gt 0){'Magenta'}else{'Green'})
Write-Host "Recommendations: $($recommendations.Count)" -ForegroundColor $(if($recommendations.Count -gt 0){'Yellow'}else{'Green'})
Write-Host ""
Write-Host "Reports saved to: $outputDir" -ForegroundColor Cyan
Write-Host ""

# Open HTML report
$response = Read-Host "Open full HTML report in browser? (Y/N)"
if ($response -eq 'Y' -or $response -eq 'y') {
    Start-Process "$outputDir\Full-Report.html"
}

Write-Host ""
Write-Host "Security audit complete!" -ForegroundColor Green
Write-Host ""
