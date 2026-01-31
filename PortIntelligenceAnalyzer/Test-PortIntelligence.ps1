<#
.SYNOPSIS
Example usage and testing script for Port Intelligence Analyzer

.DESCRIPTION
Demonstrates all features of the Port Intelligence Analyzer module with various examples.
Run this script to test the module functionality.
#>

# Import the module
Import-Module "$PSScriptRoot\PortIntelligenceAnalyzer.psd1" -Force

Write-Host @"
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    PORT INTELLIGENCE ANALYZER - TEST SUITE                    ║
║                         Enterprise Security Tool v1.0                         ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Host ""

# Function to display menu
function Show-Menu {
    Write-Host "Select a test to run:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  1. Basic Port Scan (All Listening Ports)" -ForegroundColor White
    Write-Host "  2. High-Risk Ports Only" -ForegroundColor White
    Write-Host "  3. Specific Port Analysis (e.g., 445)" -ForegroundColor White
    Write-Host "  4. Export to HTML Report" -ForegroundColor White
    Write-Host "  5. Export to JSON" -ForegroundColor White
    Write-Host "  6. Export to CSV" -ForegroundColor White
    Write-Host "  7. Console Table View" -ForegroundColor White
    Write-Host "  8. Watch for Port Changes (30 seconds)" -ForegroundColor White
    Write-Host "  9. Service Mapping Test" -ForegroundColor White
    Write-Host " 10. Full Analysis with All Features" -ForegroundColor White
    Write-Host "  0. Exit" -ForegroundColor Gray
    Write-Host ""
}

# Main loop
do {
    Show-Menu
    $choice = Read-Host "Enter your choice (0-10)"
    Write-Host ""
    
    switch ($choice) {
        "1" {
            Write-Host "Running basic port scan..." -ForegroundColor Cyan
            Write-Host ""
            $ports = Get-PortIntelligence
            $ports | Format-Table LocalPort, Protocol, ProcessName, ServiceName, Risk, BindingScope -AutoSize
            Write-Host ""
            Write-Host "Total ports found: $($ports.Count)" -ForegroundColor Green
        }
        
        "2" {
            Write-Host "Scanning for high-risk ports..." -ForegroundColor Cyan
            Write-Host ""
            $highRiskPorts = Get-PortIntelligence -RiskLevel Critical,High
            if ($highRiskPorts) {
                $highRiskPorts | Export-PortReport -Format Console
            }
            else {
                Write-Host "No high-risk ports found! ✓" -ForegroundColor Green
            }
        }
        
        "3" {
            $portNum = Read-Host "Enter port number to analyze"
            Write-Host ""
            Write-Host "Analyzing port $portNum..." -ForegroundColor Cyan
            Write-Host ""
            $portAnalysis = Get-PortIntelligence -Port $portNum
            if ($portAnalysis) {
                Write-Host "PORT DETAILS:" -ForegroundColor Yellow
                Write-Host ("─" * 80) -ForegroundColor Gray
                $portAnalysis | Format-List LocalPort, Protocol, State, ProcessName, ProcessId, 
                                           ProcessUser, ServiceName, PortName, Category, Purpose, 
                                           Risk, RiskReason, Recommendation, BindingScope, 
                                           SignatureStatus, IsSuspicious
            }
            else {
                Write-Host "Port $portNum is not open or listening." -ForegroundColor Yellow
            }
        }
        
        "4" {
            Write-Host "Generating HTML report..." -ForegroundColor Cyan
            $outputPath = "$PSScriptRoot\Reports\PortIntelligenceReport.html"
            New-Item -Path "$PSScriptRoot\Reports" -ItemType Directory -Force | Out-Null
            Get-PortIntelligence | Export-PortReport -Format HTML -OutputPath $outputPath -OpenAfterExport
            Write-Host "HTML report generated and opened in browser." -ForegroundColor Green
        }
        
        "5" {
            Write-Host "Exporting to JSON..." -ForegroundColor Cyan
            $outputPath = "$PSScriptRoot\Reports\PortIntelligence.json"
            New-Item -Path "$PSScriptRoot\Reports" -ItemType Directory -Force | Out-Null
            Get-PortIntelligence | Export-PortReport -Format JSON -OutputPath $outputPath
        }
        
        "6" {
            Write-Host "Exporting to CSV..." -ForegroundColor Cyan
            $outputPath = "$PSScriptRoot\Reports\PortIntelligence.csv"
            New-Item -Path "$PSScriptRoot\Reports" -ItemType Directory -Force | Out-Null
            Get-PortIntelligence | Export-PortReport -Format CSV -OutputPath $outputPath
        }
        
        "7" {
            Write-Host "Generating console report..." -ForegroundColor Cyan
            Write-Host ""
            Get-PortIntelligence | Export-PortReport -Format Console
        }
        
        "8" {
            Write-Host "Starting port monitoring for 30 seconds..." -ForegroundColor Cyan
            Write-Host "Open or close applications to see port changes detected!" -ForegroundColor Yellow
            Write-Host ""
            Watch-PortChanges -IntervalSeconds 5 -AlertOnNewPorts -Duration 0.5
        }
        
        "9" {
            Write-Host "Testing service mapping..." -ForegroundColor Cyan
            Write-Host ""
            $testPorts = Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen'} | Select-Object -First 5
            foreach ($conn in $testPorts) {
                $serviceInfo = Get-PortServiceMapping -ProcessId $conn.OwningProcess -Port $conn.LocalPort
                Write-Host "Port $($conn.LocalPort) - PID $($conn.OwningProcess):" -ForegroundColor Yellow
                Write-Host "  Service: $($serviceInfo.ServiceName)" -ForegroundColor White
                Write-Host "  Display: $($serviceInfo.DisplayName)" -ForegroundColor White
                Write-Host "  Binary: $($serviceInfo.BinaryPath)" -ForegroundColor Gray
                Write-Host "  Is Service: $($serviceInfo.IsWindowsService)" -ForegroundColor White
                Write-Host ""
            }
        }
        
        "10" {
            Write-Host "Running FULL ANALYSIS with all features..." -ForegroundColor Cyan
            Write-Host ""
            
            # Get all port intelligence
            Write-Host "Phase 1: Collecting port intelligence..." -ForegroundColor Yellow
            $allPorts = Get-PortIntelligence
            Write-Host "  ✓ Collected data on $($allPorts.Count) ports" -ForegroundColor Green
            Write-Host ""
            
            # Show console report
            Write-Host "Phase 2: Generating detailed console report..." -ForegroundColor Yellow
            $allPorts | Export-PortReport -Format Console
            Write-Host ""
            
            # Show high-risk summary
            Write-Host "Phase 3: High-Risk Port Summary..." -ForegroundColor Yellow
            $criticalPorts = $allPorts | Where-Object {$_.Risk -eq 'Critical'}
            if ($criticalPorts) {
                Write-Host "  🔴 CRITICAL RISK PORTS:" -ForegroundColor Red
                foreach ($port in $criticalPorts) {
                    Write-Host "     Port $($port.LocalPort) - $($port.PortName) - $($port.BindingScope)" -ForegroundColor Red
                }
            }
            Write-Host ""
            
            # Show suspicious ports
            $suspiciousPorts = $allPorts | Where-Object {$_.IsSuspicious}
            if ($suspiciousPorts) {
                Write-Host "  ⚠️  SUSPICIOUS PORTS DETECTED:" -ForegroundColor Magenta
                foreach ($port in $suspiciousPorts) {
                    Write-Host "     Port $($port.LocalPort) - $($port.ProcessName) - $($port.RiskReason)" -ForegroundColor Magenta
                }
            }
            else {
                Write-Host "  ✓ No suspicious ports detected" -ForegroundColor Green
            }
            Write-Host ""
            
            # Export all formats
            Write-Host "Phase 4: Exporting reports to all formats..." -ForegroundColor Yellow
            New-Item -Path "$PSScriptRoot\Reports" -ItemType Directory -Force | Out-Null
            
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $allPorts | Export-PortReport -Format HTML -OutputPath "$PSScriptRoot\Reports\Full-Report-$timestamp.html"
            $allPorts | Export-PortReport -Format JSON -OutputPath "$PSScriptRoot\Reports\Full-Report-$timestamp.json"
            $allPorts | Export-PortReport -Format CSV -OutputPath "$PSScriptRoot\Reports\Full-Report-$timestamp.csv"
            
            Write-Host "  ✓ Reports saved to: $PSScriptRoot\Reports\" -ForegroundColor Green
            Write-Host ""
            
            Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
            Write-Host "FULL ANALYSIS COMPLETE" -ForegroundColor Cyan
            Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        }
        
        "0" {
            Write-Host "Exiting..." -ForegroundColor Gray
            break
        }
        
        default {
            Write-Host "Invalid choice. Please select 0-10." -ForegroundColor Red
        }
    }
    
    if ($choice -ne "0") {
        Write-Host ""
        Write-Host "Press Enter to continue..." -ForegroundColor Gray
        Read-Host
        Clear-Host
    }
    
} while ($choice -ne "0")

Write-Host ""
Write-Host "Thank you for using Port Intelligence Analyzer!" -ForegroundColor Cyan
Write-Host ""
