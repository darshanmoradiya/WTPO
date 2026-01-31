<#
.SYNOPSIS
Monitors network ports for changes in real-time.

.DESCRIPTION
Continuously monitors the system for new ports being opened, existing ports being closed,
or changes in port risk status. Can alert on suspicious activity.

.PARAMETER IntervalSeconds
Time between scans in seconds (default: 30).

.PARAMETER AlertOnNewPorts
Show alert when new ports are detected.

.PARAMETER AlertOnRiskChange
Show alert when port risk level changes.

.PARAMETER AlertOnSuspicious
Show alert for suspicious ports only.

.PARAMETER Duration
How long to monitor (in minutes). Leave empty for continuous monitoring.

.EXAMPLE
Watch-PortChanges
Starts continuous monitoring with default 30-second intervals.

.EXAMPLE
Watch-PortChanges -IntervalSeconds 10 -AlertOnNewPorts
Monitors every 10 seconds and alerts on new ports.

.EXAMPLE
Watch-PortChanges -Duration 60 -AlertOnSuspicious
Monitors for 60 minutes, alerting only on suspicious activity.
#>
function Watch-PortChanges {
    [CmdletBinding()]
    param(
        [int]$IntervalSeconds = 30,
        [switch]$AlertOnNewPorts,
        [switch]$AlertOnRiskChange,
        [switch]$AlertOnSuspicious,
        [int]$Duration
    )
    
    begin {
        Write-PortIntelligenceLog "Starting port monitoring (Press Ctrl+C to stop)..." -Level Info
        Write-Host "Scan interval: $IntervalSeconds seconds" -ForegroundColor Cyan
        
        if ($Duration) {
            Write-Host "Monitoring duration: $Duration minutes" -ForegroundColor Cyan
        }
        else {
            Write-Host "Monitoring: Continuous (until stopped)" -ForegroundColor Cyan
        }
        
        Write-Host ""
        
        $baseline = @{}
        $startTime = Get-Date
        $scanCount = 0
    }
    
    process {
        try {
            while ($true) {
                $scanCount++
                $currentTime = Get-Date
                
                # Check if duration limit reached
                if ($Duration -and (($currentTime - $startTime).TotalMinutes -ge $Duration)) {
                    Write-PortIntelligenceLog "Monitoring duration complete." -Level Info
                    break
                }
                
                Write-Host "[$($currentTime.ToString('HH:mm:ss'))] Scan #$scanCount - Checking ports..." -ForegroundColor Gray
                
                # Get current port state
                $currentPorts = Get-PortIntelligence
                $currentPortMap = @{}
                
                foreach ($port in $currentPorts) {
                    $key = "$($port.Protocol):$($port.LocalPort):$($port.ProcessId)"
                    $currentPortMap[$key] = $port
                }
                
                # Detect changes
                if ($baseline.Count -gt 0) {
                    # Check for new ports
                    foreach ($key in $currentPortMap.Keys) {
                        if (-not $baseline.ContainsKey($key)) {
                            $port = $currentPortMap[$key]
                            $shouldAlert = $false
                            
                            if ($AlertOnNewPorts) { $shouldAlert = $true }
                            if ($AlertOnSuspicious -and $port.IsSuspicious) { $shouldAlert = $true }
                            if ($port.Risk -in @('Critical', 'High')) { $shouldAlert = $true }
                            
                            if ($shouldAlert) {
                                $riskEmoji = Get-RiskEmoji -Risk $port.Risk
                                Write-Host ""
                                Write-Host "  🆕 NEW PORT DETECTED:" -ForegroundColor Yellow
                                Write-Host "     Port: $($port.LocalPort) ($($port.Protocol))" -ForegroundColor White
                                Write-Host "     Process: $($port.ProcessName) (PID: $($port.ProcessId))" -ForegroundColor White
                                Write-Host "     Service: $($port.PortName)" -ForegroundColor White
                                Write-Host "     Risk: $riskEmoji $($port.Risk)" -ForegroundColor (Get-ColorForRisk -Risk $port.Risk)
                                Write-Host "     Binding: $($port.BindingScope)" -ForegroundColor White
                                if ($port.IsSuspicious) {
                                    Write-Host "     ⚠️  SUSPICIOUS: $($port.RiskReason)" -ForegroundColor Magenta
                                }
                                Write-Host ""
                            }
                        }
                    }
                    
                    # Check for closed ports
                    foreach ($key in $baseline.Keys) {
                        if (-not $currentPortMap.ContainsKey($key)) {
                            $port = $baseline[$key]
                            Write-Host ""
                            Write-Host "  ❌ PORT CLOSED:" -ForegroundColor Gray
                            Write-Host "     Port: $($port.LocalPort) ($($port.Protocol))" -ForegroundColor White
                            Write-Host "     Process: $($port.ProcessName) (PID: $($port.ProcessId))" -ForegroundColor White
                            Write-Host ""
                        }
                    }
                    
                    # Check for risk changes
                    if ($AlertOnRiskChange) {
                        foreach ($key in $currentPortMap.Keys) {
                            if ($baseline.ContainsKey($key)) {
                                $oldPort = $baseline[$key]
                                $newPort = $currentPortMap[$key]
                                
                                if ($oldPort.Risk -ne $newPort.Risk) {
                                    Write-Host ""
                                    Write-Host "  🔄 RISK LEVEL CHANGED:" -ForegroundColor Yellow
                                    Write-Host "     Port: $($newPort.LocalPort) ($($newPort.Protocol))" -ForegroundColor White
                                    Write-Host "     Old Risk: $(Get-RiskEmoji -Risk $oldPort.Risk) $($oldPort.Risk)" -ForegroundColor (Get-ColorForRisk -Risk $oldPort.Risk)
                                    Write-Host "     New Risk: $(Get-RiskEmoji -Risk $newPort.Risk) $($newPort.Risk)" -ForegroundColor (Get-ColorForRisk -Risk $newPort.Risk)
                                    Write-Host ""
                                }
                            }
                        }
                    }
                }
                else {
                    Write-Host "  Baseline established: $($currentPortMap.Count) ports" -ForegroundColor Green
                }
                
                # Update baseline
                $baseline = $currentPortMap
                
                # Wait for next interval
                Start-Sleep -Seconds $IntervalSeconds
            }
        }
        catch {
            Write-PortIntelligenceLog "Monitoring interrupted: $_" -Level Warning
        }
    }
    
    end {
        Write-PortIntelligenceLog "Port monitoring stopped. Total scans: $scanCount" -Level Info
    }
}

Export-ModuleMember -Function Watch-PortChanges
