# Port Intelligence Analyzer - Quick Start Guide

## ⚡ 5-Minute Quick Start

### Step 1: Open PowerShell as Administrator

Right-click PowerShell and select "Run as Administrator"

### Step 2: Navigate to the Module Directory

```powershell
cd "D:\darshan\project\WTPO\PortIntelligenceAnalyzer"
```

### Step 3: Import the Module

```powershell
Import-Module .\PortIntelligenceAnalyzer.psd1 -Force
```

### Step 4: Run Your First Scan

```powershell
# Simple scan
Get-PortIntelligence | Export-PortReport -Format Console
```

## 🎯 Common Scenarios

### Scenario 1: Security Audit
**Goal**: Find all high-risk ports on your system

```powershell
# Show critical and high-risk ports
Get-PortIntelligence -RiskLevel Critical,High | Export-PortReport -Format Console

# Export to HTML for sharing
Get-PortIntelligence -RiskLevel Critical,High | Export-PortReport -Format HTML -OutputPath "C:\SecurityAudit.html" -OpenAfterExport
```

### Scenario 2: Investigate Specific Port
**Goal**: Deep dive into why port 445 (SMB) is open

```powershell
$port445 = Get-PortIntelligence -Port 445

# Show detailed information
$port445 | Format-List *

# See specific details
Write-Host "Port: $($port445.LocalPort)"
Write-Host "Risk: $($port445.Risk)"
Write-Host "Process: $($port445.ProcessName) (PID: $($port445.ProcessId))"
Write-Host "Service: $($port445.ServiceName)"
Write-Host "Purpose: $($port445.Purpose)"
Write-Host "Recommendation: $($port445.Recommendation)"
Write-Host "Binding: $($port445.BindingScope)"
```

### Scenario 3: Monitor for Suspicious Activity
**Goal**: Watch for new ports opening in real-time

```powershell
# Monitor for 5 minutes, alert on new ports and suspicious activity
Watch-PortChanges -IntervalSeconds 10 -AlertOnNewPorts -AlertOnSuspicious -Duration 5
```

### Scenario 4: Find Non-Service Processes
**Goal**: Discover processes that opened ports but aren't Windows services

```powershell
Get-PortIntelligence | Where-Object {
    -not $_.IsWindowsNative -and $_.Category -notin @("Windows Native", "Development")
} | Select-Object LocalPort, ProcessName, Category, Risk, Purpose | Format-Table
```

### Scenario 5: Compliance Report
**Goal**: Generate a timestamped report for audit purposes

```powershell
# Create reports directory
New-Item -Path "C:\ComplianceReports" -ItemType Directory -Force

# Generate all report formats
Get-PortIntelligence | Export-PortReport -Format HTML -OutputPath "C:\ComplianceReports\ports.html" -IncludeTimestamp
Get-PortIntelligence | Export-PortReport -Format JSON -OutputPath "C:\ComplianceReports\ports.json" -IncludeTimestamp
Get-PortIntelligence | Export-PortReport -Format CSV -OutputPath "C:\ComplianceReports\ports.csv" -IncludeTimestamp
```

### Scenario 6: Find Database Ports
**Goal**: Locate all database services and check exposure

```powershell
Get-PortIntelligence | Where-Object {
    $_.Category -eq "Database"
} | Select-Object LocalPort, PortName, Risk, BindingScope, ProcessName | Format-Table
```

### Scenario 7: Emergency Response
**Goal**: Find and close suspicious high-risk ports

```powershell
# Find suspicious ports
$suspicious = Get-PortIntelligence | Where-Object {$_.IsSuspicious -eq $true}

# Review them
$suspicious | Export-PortReport -Format Console

# Close a specific suspicious port (requires admin)
Close-SuspiciousPort -Port 4444 -Action KillProcess -Force

# Or block with firewall instead
Close-SuspiciousPort -Port 4444 -Action BlockFirewall
```

### Scenario 8: Development Environment Check
**Goal**: See what development tools have ports open

```powershell
Get-PortIntelligence | Where-Object {
    $_.Category -eq "Development" -or 
    $_.ProcessName -in @("node", "python", "java", "dotnet", "code")
} | Select-Object LocalPort, ProcessName, PortName, BindingScope | Format-Table
```

### Scenario 9: Check RDP Exposure
**Goal**: Verify if Remote Desktop is exposed to the internet

```powershell
$rdp = Get-PortIntelligence -Port 3389

if ($rdp) {
    Write-Host "RDP Status:" -ForegroundColor Yellow
    Write-Host "  Port: 3389" -ForegroundColor White
    Write-Host "  Binding: $($rdp.BindingScope)" -ForegroundColor White
    Write-Host "  Risk: $($rdp.Risk)" -ForegroundColor (Get-ColorForRisk -Risk $rdp.Risk)
    
    if ($rdp.BindingScope -like "*Public*") {
        Write-Host "  ⚠️  WARNING: RDP is exposed to all interfaces!" -ForegroundColor Red
        Write-Host "  Recommendation: $($rdp.Recommendation)" -ForegroundColor Yellow
    }
    else {
        Write-Host "  ✓ RDP is bound to localhost only" -ForegroundColor Green
    }
}
else {
    Write-Host "✓ RDP (port 3389) is not open" -ForegroundColor Green
}
```

### Scenario 10: Scheduled Security Scan
**Goal**: Create a scheduled task to run daily scans

```powershell
# Create script for scheduled task
$scriptContent = @'
Import-Module "D:\darshan\project\WTPO\PortIntelligenceAnalyzer\PortIntelligenceAnalyzer.psd1"

$reportPath = "C:\SecurityScans\DailyScan-$(Get-Date -Format 'yyyyMMdd').html"
New-Item -Path "C:\SecurityScans" -ItemType Directory -Force | Out-Null

Get-PortIntelligence | Export-PortReport -Format HTML -OutputPath $reportPath

# Send email alert for critical ports (customize with your email settings)
$criticalPorts = Get-PortIntelligence -RiskLevel Critical
if ($criticalPorts) {
    # Add your email notification logic here
    Write-Host "⚠️ Critical ports detected: $($criticalPorts.Count)"
}
'@

$scriptContent | Out-File -FilePath "C:\Scripts\DailyPortScan.ps1" -Encoding UTF8

Write-Host "Scheduled scan script created at: C:\Scripts\DailyPortScan.ps1"
Write-Host "Add to Task Scheduler to run daily"
```

## 🔧 Troubleshooting

### Issue: "Access Denied" or Limited Information

**Solution**: Run PowerShell as Administrator
```powershell
# Check if running as admin
if (-not (Test-IsAdministrator)) {
    Write-Host "Please run PowerShell as Administrator for full functionality"
}
```

### Issue: Module Not Found

**Solution**: Use full path when importing
```powershell
Import-Module "D:\darshan\project\WTPO\PortIntelligenceAnalyzer\PortIntelligenceAnalyzer.psd1" -Force
```

### Issue: Execution Policy Error

**Solution**: Temporarily allow script execution
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
```

### Issue: Slow Performance

**Solution**: Limit scope of scan
```powershell
# Only scan TCP ports
Get-PortIntelligence -Protocol TCP

# Only specific risk levels
Get-PortIntelligence -RiskLevel Critical,High
```

## 📊 Understanding the Output

### Risk Levels

- **🔴 Critical**: Immediate security concern, typically exposed to network
- **🟠 High**: Significant risk, requires attention
- **🟡 Medium**: Moderate risk, review configuration
- **🟢 Low**: Normal operation, minimal concern
- **⚪ Unknown**: Unrecognized service, investigate

### Binding Scope

- **All Interfaces (Public)**: Port accessible from network (0.0.0.0)
- **Localhost Only (Private)**: Port only accessible locally (127.0.0.1)
- **Specific Interface**: Port bound to particular IP

### Suspicious Indicators

Ports flagged as suspicious may indicate:
- Unsigned executable
- Non-service process on unusual port
- Multiple risk factors combined
- Port > 10000 with unknown purpose

## 🎓 Best Practices

1. **Run as Administrator**: Always use admin privileges for complete information
2. **Regular Scans**: Run weekly or after system changes
3. **Baseline Creation**: Establish normal state with `Watch-PortChanges` 
4. **Document Findings**: Use HTML reports for sharing with team
5. **Close Unused Ports**: Disable unnecessary services
6. **Review Localhost**: Even localhost-only ports should be audited
7. **Monitor Changes**: Use watch mode during maintenance windows

## 📚 Additional Resources

- Full documentation: See README.md
- Interactive testing: Run `.\Test-PortIntelligence.ps1`
- Command help: `Get-Help Get-PortIntelligence -Full`

---

**Need Help?** Check the README.md or run the interactive test suite for examples.
