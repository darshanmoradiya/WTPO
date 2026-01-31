# Port Intelligence Analyzer - Simple Runner
# Just run: .\Run.ps1

# Import module
Import-Module "$PSScriptRoot\PortIntelligenceAnalyzer.psd1" -Force -ErrorAction Stop

Clear-Host

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "   PORT INTELLIGENCE ANALYZER - SIMPLE MODE" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Simple menu
Write-Host "What would you like to do?" -ForegroundColor Yellow
Write-Host ""
Write-Host "  1. Scan All Ports" -ForegroundColor White
Write-Host "  2. Find Dangerous Ports Only" -ForegroundColor Red
Write-Host "  3. Generate HTML Report" -ForegroundColor White
Write-Host "  4. Monitor Ports (Real-time)" -ForegroundColor White
Write-Host "  5. Exit" -ForegroundColor Gray
Write-Host ""

$choice = Read-Host "Enter number (1-5)"

switch ($choice) {
    "1" {
        Write-Host ""
        Write-Host "Scanning all ports..." -ForegroundColor Cyan
        Write-Host ""
        Get-PortIntelligence | Export-PortReport -Format Console
    }
    
    "2" {
        Write-Host ""
        Write-Host "Finding dangerous ports..." -ForegroundColor Red
        Write-Host ""
        Get-PortIntelligence -RiskLevel Critical,High | Export-PortReport -Format Console
    }
    
    "3" {
        Write-Host ""
        $reportPath = "$PSScriptRoot\PortReport-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
        Write-Host "Generating HTML report..." -ForegroundColor Cyan
        Get-PortIntelligence | Export-PortReport -Format HTML -OutputPath $reportPath
        Write-Host ""
        Write-Host "Report saved: $reportPath" -ForegroundColor Green
        Write-Host ""
        $open = Read-Host "Open in browser? (Y/N)"
        if ($open -eq 'Y' -or $open -eq 'y') {
            Start-Process $reportPath
        }
    }
    
    "4" {
        Write-Host ""
        Write-Host "Monitoring ports for 2 minutes..." -ForegroundColor Cyan
        Write-Host "Press Ctrl+C to stop early" -ForegroundColor Gray
        Write-Host ""
        Watch-PortChanges -IntervalSeconds 10 -AlertOnNewPorts -Duration 2
    }
    
    "5" {
        Write-Host ""
        Write-Host "Goodbye!" -ForegroundColor Gray
        exit
    }
    
    default {
        Write-Host ""
        Write-Host "Invalid choice. Please run .\Run.ps1 again." -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Done! Run .\Run.ps1 again anytime." -ForegroundColor Green
Write-Host ""
