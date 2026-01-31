<#
.SYNOPSIS
Closes suspicious or unwanted network ports.

.DESCRIPTION
Provides remediation actions for suspicious ports including:
- Killing the owning process
- Creating firewall rules to block the port
- Stopping associated Windows services

.PARAMETER Port
The port number to close.

.PARAMETER ProcessId
The process ID owning the port.

.PARAMETER Action
The remediation action to take: KillProcess, BlockFirewall, StopService, or All.

.PARAMETER Force
Skip confirmation prompts.

.EXAMPLE
Close-SuspiciousPort -Port 4444 -ProcessId 1234 -Action KillProcess
Kills the process owning port 4444.

.EXAMPLE
Close-SuspiciousPort -Port 3389 -Action BlockFirewall
Creates a firewall rule to block RDP.

.EXAMPLE
Get-PortIntelligence -RiskLevel Critical | Where-Object {$_.IsSuspicious} | Close-SuspiciousPort -Action All -Force
Automatically remediates all suspicious critical ports.
#>
function Close-SuspiciousPort {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias("LocalPort")]
        [int]$Port,
        
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [int]$ProcessId,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("KillProcess", "BlockFirewall", "StopService", "All")]
        [string]$Action,
        
        [switch]$Force
    )
    
    begin {
        # Check for administrator privileges
        if (-not (Test-IsAdministrator)) {
            Write-PortIntelligenceLog "Administrator privileges required for remediation actions." -Level Error
            throw "This cmdlet requires administrator privileges."
        }
    }
    
    process {
        try {
            Write-PortIntelligenceLog "Analyzing port $Port for remediation..." -Level Info
            
            # Get port information
            $portInfo = Get-PortIntelligence -Port $Port
            if (-not $portInfo) {
                Write-PortIntelligenceLog "Port $Port not found or not open." -Level Warning
                return
            }
            
            # Use the first matching port if multiple
            if ($portInfo -is [array]) {
                $portInfo = $portInfo[0]
            }
            
            # Confirmation prompt
            if (-not $Force) {
                Write-Host ""
                Write-Host "PORT REMEDIATION DETAILS:" -ForegroundColor Yellow
                Write-Host "  Port: $($portInfo.LocalPort) ($($portInfo.Protocol))" -ForegroundColor White
                Write-Host "  Process: $($portInfo.ProcessName) (PID: $($portInfo.ProcessId))" -ForegroundColor White
                Write-Host "  Service: $($portInfo.ServiceName)" -ForegroundColor White
                Write-Host "  Risk: $($portInfo.Risk)" -ForegroundColor (Get-ColorForRisk -Risk $portInfo.Risk)
                Write-Host "  Action: $Action" -ForegroundColor Cyan
                Write-Host ""
                
                $confirmation = Read-Host "Are you sure you want to proceed? (yes/no)"
                if ($confirmation -ne "yes") {
                    Write-PortIntelligenceLog "Remediation cancelled by user." -Level Warning
                    return
                }
            }
            
            # Perform remediation actions
            if ($Action -in @("KillProcess", "All")) {
                if ($portInfo.ProcessId -gt 0 -and $portInfo.ProcessId -ne 4) {
                    if ($PSCmdlet.ShouldProcess("Process $($portInfo.ProcessName) (PID: $($portInfo.ProcessId))", "Kill Process")) {
                        try {
                            Stop-Process -Id $portInfo.ProcessId -Force -ErrorAction Stop
                            Write-PortIntelligenceLog "Successfully killed process $($portInfo.ProcessName) (PID: $($portInfo.ProcessId))" -Level Success
                        }
                        catch {
                            Write-PortIntelligenceLog "Failed to kill process: $_" -Level Error
                        }
                    }
                }
                else {
                    Write-PortIntelligenceLog "Cannot kill system process (PID: $($portInfo.ProcessId))" -Level Warning
                }
            }
            
            if ($Action -in @("BlockFirewall", "All")) {
                if ($PSCmdlet.ShouldProcess("Port $Port", "Create Firewall Block Rule")) {
                    try {
                        $ruleName = "Block_Port_$Port`_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
                        New-NetFirewallRule -DisplayName $ruleName `
                                           -Direction Inbound `
                                           -Protocol $portInfo.Protocol `
                                           -LocalPort $Port `
                                           -Action Block `
                                           -Enabled True `
                                           -ErrorAction Stop | Out-Null
                        
                        Write-PortIntelligenceLog "Successfully created firewall rule: $ruleName" -Level Success
                    }
                    catch {
                        Write-PortIntelligenceLog "Failed to create firewall rule: $_" -Level Error
                    }
                }
            }
            
            if ($Action -in @("StopService", "All")) {
                if ($portInfo.ServiceName) {
                    if ($PSCmdlet.ShouldProcess("Service $($portInfo.ServiceName)", "Stop Service")) {
                        try {
                            Stop-Service -Name $portInfo.ServiceName -Force -ErrorAction Stop
                            Write-PortIntelligenceLog "Successfully stopped service: $($portInfo.ServiceName)" -Level Success
                        }
                        catch {
                            Write-PortIntelligenceLog "Failed to stop service: $_" -Level Error
                        }
                    }
                }
                else {
                    Write-PortIntelligenceLog "No service associated with this port" -Level Warning
                }
            }
            
            Write-Host ""
        }
        catch {
            Write-PortIntelligenceLog "Error during remediation: $_" -Level Error
            throw
        }
    }
}

Export-ModuleMember -Function Close-SuspiciousPort
