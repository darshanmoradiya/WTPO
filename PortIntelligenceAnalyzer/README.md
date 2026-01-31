# Port Intelligence Analyzer

> **Enterprise-grade port forensics analyzer that explains why ports are open and assesses security posture on Windows systems.**

## 🔍 Overview

Port Intelligence Analyzer is a comprehensive PowerShell tool that goes beyond basic port scanning. It provides deep forensics by combining OS-level APIs with threat intelligence to explain **exactly why each port is open** and assess its security posture. Think of it as "Why Is This Port Open?" for Windows.

## ✨ Key Features

### Phase 1 (MVP) - Currently Implemented

- **🔎 Deep Port Enumeration**: Multi-source port detection using Get-NetTCPConnection and Get-NetUDPEndpoint
- **🔗 Process & Service Mapping**: Links ports to processes, services, and binary paths via WMI/CIM
- **⚠️ Risk Assessment Engine**: Intelligent categorization of ports as Critical, High, Medium, Low risk
- **👤 User Context Analysis**: Identifies which user account is running each service (SYSTEM, LocalService, etc.)
- **🌐 Network Binding Detection**: Identifies if ports bind to all interfaces (0.0.0.0) or localhost (127.0.0.1)
- **✍️ Digital Signature Verification**: Checks if executables are properly signed
- **🎨 Color-Coded CLI Output**: Beautiful terminal interface with risk indicators (🔴🟠🟡🟢⚪)
- **📊 Multiple Export Formats**: JSON, CSV, HTML reports with professional styling
- **👁️ Real-Time Monitoring**: Watch for new ports, closed ports, and risk changes
- **🛡️ Remediation Actions**: Kill processes, create firewall rules, stop services

## 🚀 Quick Start

### Simple Way (Recommended)

1. Open PowerShell and navigate to the folder:
```powershell
cd "d:\darshan\project\WTPO\PortIntelligenceAnalyzer"
```

2. Run the simple launcher:
```powershell
.\Run.ps1
```

3. Choose what you want to do from the menu!

That's it! The simple runner guides you through everything.

### Advanced Way (For PowerShell Users)

1. Import the module:
```powershell
Import-Module .\PortIntelligenceAnalyzer.psd1
```

2. Run commands directly:
```powershell
Get-PortIntelligence | Export-PortReport -Format Console
```

### Basic Usage

```powershell
# Scan all listening ports
Get-PortIntelligence

# Show only high-risk ports
Get-PortIntelligence -RiskLevel Critical,High

# Analyze a specific port
Get-PortIntelligence -Port 445

# Export to HTML report
Get-PortIntelligence | Export-PortReport -Format HTML -OutputPath "C:\Reports\ports.html" -OpenAfterExport

# Monitor for changes
Watch-PortChanges -IntervalSeconds 10 -AlertOnNewPorts

# Close suspicious ports (requires admin)
Get-PortIntelligence -RiskLevel Critical | Where-Object {$_.IsSuspicious} | Close-SuspiciousPort -Action KillProcess -Force
```

### Interactive Testing

Run the comprehensive test suite:
```powershell
.\Test-PortIntelligence.ps1
```

This provides an interactive menu to test all features.

## 📖 Command Reference

### Get-PortIntelligence

Main scanning function that collects comprehensive port intelligence.

**Parameters:**
- `-IncludeListeningOnly` - Show only listening ports (default)
- `-IncludeEstablished` - Include active connections
- `-Protocol` - Filter by TCP, UDP, or Both
- `-Port` - Analyze specific port number
- `-RiskLevel` - Filter by Critical, High, Medium, Low, Unknown

**Example:**
```powershell
Get-PortIntelligence -RiskLevel Critical,High | Format-Table LocalPort, ProcessName, Risk, BindingScope
```

### Get-PortServiceMapping

Maps processes to Windows services and retrieves service details.

**Parameters:**
- `-ProcessId` - Process ID to query (required)
- `-Port` - Optional port context

**Example:**
```powershell
Get-PortServiceMapping -ProcessId 1234 -Port 445
```

### Get-PortRiskAssessment

Analyzes security risk based on multiple factors.

**Parameters:**
- `-Port` - Port number (required)
- `-LocalAddress` - Binding address
- `-ProcessPath` - Executable path
- `-SignatureStatus` - Digital signature status
- `-ServiceInfo` - Service information hashtable

**Example:**
```powershell
Get-PortRiskAssessment -Port 3389 -LocalAddress "0.0.0.0"
```

### Export-PortReport

Exports analysis to various formats with professional styling.

**Parameters:**
- `-PortData` - Port intelligence objects (pipeline input)
- `-Format` - JSON, CSV, HTML, or Console (required)
- `-OutputPath` - File path for export
- `-IncludeTimestamp` - Add timestamp to filename
- `-OpenAfterExport` - Open HTML report automatically

**Examples:**
```powershell
# HTML with auto-open
Get-PortIntelligence | Export-PortReport -Format HTML -OutputPath ".\report.html" -OpenAfterExport

# JSON with timestamp
Get-PortIntelligence | Export-PortReport -Format JSON -OutputPath ".\report.json" -IncludeTimestamp

# Console output (no file)
Get-PortIntelligence | Export-PortReport -Format Console
```

### Watch-PortChanges

Real-time monitoring for port changes and suspicious activity.

**Parameters:**
- `-IntervalSeconds` - Scan interval (default: 30)
- `-AlertOnNewPorts` - Alert when new ports detected
- `-AlertOnRiskChange` - Alert on risk level changes
- `-AlertOnSuspicious` - Alert only for suspicious ports
- `-Duration` - Monitoring duration in minutes (empty = continuous)

**Examples:**
```powershell
# Continuous monitoring with all alerts
Watch-PortChanges -IntervalSeconds 10 -AlertOnNewPorts -AlertOnSuspicious

# Monitor for 1 hour
Watch-PortChanges -Duration 60 -AlertOnRiskChange
```

### Close-SuspiciousPort

Remediation actions for suspicious or high-risk ports (requires Administrator).

**Parameters:**
- `-Port` - Port number to close (required)
- `-ProcessId` - Process ID (optional, pipeline input)
- `-Action` - KillProcess, BlockFirewall, StopService, or All (required)
- `-Force` - Skip confirmation prompts

**Examples:**
```powershell
# Kill process on port 4444
Close-SuspiciousPort -Port 4444 -ProcessId 1234 -Action KillProcess

# Block port 3389 with firewall
Close-SuspiciousPort -Port 3389 -Action BlockFirewall

# Full remediation with confirmation
Get-PortIntelligence -Port 8888 | Close-SuspiciousPort -Action All
```

## 🎯 Use Cases

### Security Auditing
```powershell
# Find all critical risk ports exposed to the network
Get-PortIntelligence -RiskLevel Critical | Where-Object {$_.BindingScope -like "*Public*"}
```

### Compliance Reporting
```powershell
# Generate timestamped HTML report for compliance
Get-PortIntelligence | Export-PortReport -Format HTML -OutputPath "C:\Audit\compliance.html" -IncludeTimestamp
```

### Incident Response
```powershell
# Find suspicious non-service ports
Get-PortIntelligence | Where-Object {$_.IsSuspicious -and -not $_.IsWindowsNative}
```

### Development Environment Cleanup
```powershell
# Find development ports (Node.js, Python, etc.)
Get-PortIntelligence | Where-Object {$_.Category -eq "Development"}
```

## 📊 Sample Output

### Console Report
```
═══════════════════════════════════════════════════════════════════════════════════════
                           PORT INTELLIGENCE REPORT
═══════════════════════════════════════════════════════════════════════════════════════
Generated: 2026-01-31 14:30:15  |  Total Ports: 23

RISK SUMMARY:
  🔴 Critical: 2
  🟠 High: 3
  🟡 Medium: 8
  🟢 Low: 10
  ⚠️  Suspicious: 1

Port    Proto  State      PID    Process           Service/Binary                   Risk    Purpose
----    -----  -----      ---    -------           --------------                   ----    -------
445     TCP    Listening  4      System            SMB (File Sharing)              🔴 Critical
        └─ Purpose: Windows file and printer sharing protocol
        └─ Binding: All Interfaces (Public)
        
3389    TCP    Listening  1124   svchost.exe       Remote Desktop Services         🟡 Medium
        └─ Purpose: Remote desktop access to Windows machines
        └─ Binding: All Interfaces (Public)
```

## 🏗️ Architecture

### Module Structure
```
PortIntelligenceAnalyzer/
├── PortIntelligenceAnalyzer.psd1      # Module manifest
├── PortIntelligenceAnalyzer.psm1      # Main module file
├── Private/
│   ├── Helpers.ps1                    # Utility functions
│   └── PortDatabase.ps1               # Port knowledge base
├── Public/
│   ├── Get-PortIntelligence.ps1      # Main scanner
│   ├── Get-PortServiceMapping.ps1    # Service resolver
│   ├── Get-PortRiskAssessment.ps1    # Risk calculator
│   ├── Export-PortReport.ps1         # Report generator
│   ├── Watch-PortChanges.ps1         # Real-time monitor
│   └── Close-SuspiciousPort.ps1      # Remediation
├── Reports/                           # Generated reports
└── Test-PortIntelligence.ps1         # Interactive test suite
```

## 🛡️ Risk Assessment Logic

The tool uses multi-factor risk assessment:

1. **Port Knowledge Base**: 50+ well-known ports with predefined risk levels
2. **Network Exposure**: Escalates risk for services on 0.0.0.0 vs 127.0.0.1
3. **Digital Signatures**: Flags unsigned or invalid executables
4. **Service Context**: Distinguishes Windows native vs third-party vs non-service processes
5. **Suspicious Patterns**: Detects anomalies like high ports, unsigned binaries, unusual binding

## 🔒 Security Considerations

- **Administrator Privileges**: Required for full process information and remediation actions
- **Read-Only by Default**: Scanning operations are non-invasive
- **Explicit Confirmation**: Remediation actions require confirmation unless `-Force` is used
- **Audit Trail**: All operations can be logged via `Write-PortIntelligenceLog`

## 🚧 Roadmap

### Phase 2 (Planned)
- Binary hash calculation and VirusTotal integration
- Enhanced interface binding analysis with route correlation
- Expanded port knowledge database (100+ ports)
- SIEM export format (CEF, Syslog)

### Phase 3 (Planned)
- Baseline mode with anomaly detection
- Temporal analysis for off-hours port activity
- Parent process tree visualization
- Threat intelligence API integration

### Phase 4 (Planned)
- Electron/WPF GUI dashboard
- RADAR-Scanner integration
- Slack/Teams webhook alerts
- SQLite historical database

## 🤝 Contributing

Contributions are welcome! Areas of interest:
- Additional port knowledge entries
- New export formats
- GUI development
- Threat intelligence integrations

## 📝 License

MIT License - See LICENSE file for details

## 👏 Acknowledgments

Inspired by the "Why Is This Port Open?" (WTPO) security concept and built to fill the gap in Windows port forensics tooling.

---

**Built with ❤️ for Windows Security Professionals**
