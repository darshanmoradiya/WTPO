<#
.SYNOPSIS
Gets comprehensive intelligence about open network ports on the system.

.DESCRIPTION
Performs deep port forensics by analyzing network connections, processes, services,
and binary signatures to provide detailed information about why each port is open
and assess its security posture.

.PARAMETER IncludeListeningOnly
Only show listening ports (servers). Excludes established connections.

.PARAMETER IncludeEstablished
Include established connections in addition to listening ports.

.PARAMETER Protocol
Filter by protocol (TCP, UDP, or Both).

.PARAMETER Port
Filter by specific port number.

.PARAMETER RiskLevel
Filter by risk level (Critical, High, Medium, Low, Unknown).

.EXAMPLE
Get-PortIntelligence
Shows all listening ports with full intelligence analysis.

.EXAMPLE
Get-PortIntelligence -RiskLevel Critical,High
Shows only high-risk ports.

.EXAMPLE
Get-PortIntelligence -Port 445
Analyzes port 445 specifically.

.EXAMPLE
Get-PortIntelligence -IncludeEstablished
Shows all connections including active connections.
#>
function Get-PortIntelligence {
    [CmdletBinding()]
    param(
        [switch]$IncludeListeningOnly = $true,
        [switch]$IncludeEstablished,
        [ValidateSet("TCP", "UDP", "Both")]
        [string]$Protocol = "Both",
        [int]$Port,
        [ValidateSet("Critical", "High", "Medium", "Low", "Unknown")]
        [string[]]$RiskLevel
    )
    
    begin {
        Write-PortIntelligenceLog "Starting Port Intelligence Analysis..." -Level Info
        
        # Check for administrator privileges
        if (-not (Test-IsAdministrator)) {
            Write-PortIntelligenceLog "Running without administrator privileges. Some features may be limited." -Level Warning
        }
        
        $results = @()
    }
    
    process {
        try {
            # Get TCP connections
            if ($Protocol -in @("TCP", "Both")) {
                Write-Verbose "Collecting TCP connections..."
                $tcpConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue
                
                if ($tcpConnections) {
                    foreach ($conn in $tcpConnections) {
                        # Filter based on parameters
                        if ($IncludeListeningOnly -and $conn.State -ne 'Listen') {
                            continue
                        }
                        
                        if (-not $IncludeEstablished -and $conn.State -notin @('Listen', 'Bound')) {
                            continue
                        }
                        
                        if ($Port -and $conn.LocalPort -ne $Port) {
                            continue
                        }
                        
                        # Build port intelligence object
                        $portInfo = Build-PortIntelligenceObject -Connection $conn -Protocol "TCP"
                        
                        # Apply risk filter
                        if ($RiskLevel -and $portInfo.Risk -notin $RiskLevel) {
                            continue
                        }
                        
                        $results += $portInfo
                    }
                }
            }
            
            # Get UDP endpoints
            if ($Protocol -in @("UDP", "Both")) {
                Write-Verbose "Collecting UDP endpoints..."
                $udpEndpoints = Get-NetUDPEndpoint -ErrorAction SilentlyContinue
                
                if ($udpEndpoints) {
                    foreach ($endpoint in $udpEndpoints) {
                        if ($Port -and $endpoint.LocalPort -ne $Port) {
                            continue
                        }
                        
                        # Build port intelligence object
                        $portInfo = Build-PortIntelligenceObject -Connection $endpoint -Protocol "UDP"
                        
                        # Apply risk filter
                        if ($RiskLevel -and $portInfo.Risk -notin $RiskLevel) {
                            continue
                        }
                        
                        $results += $portInfo
                    }
                }
            }
            
            Write-PortIntelligenceLog "Analysis complete. Found $($results.Count) ports." -Level Success
            
            # Sort by risk level (descending) then port number
            $results = $results | Sort-Object @{Expression = {Get-RiskLevel $_.Risk}; Descending = $true}, LocalPort
            
            return $results
        }
        catch {
            Write-PortIntelligenceLog "Error during analysis: $_" -Level Error
            throw
        }
    }
}

function Build-PortIntelligenceObject {
    <#
    .SYNOPSIS
    Builds a comprehensive port intelligence object.
    #>
    param(
        $Connection,
        [string]$Protocol
    )
    
    try {
        $localPort = $Connection.LocalPort
        $processId = $Connection.OwningProcess
        $localAddress = $Connection.LocalAddress
        $state = if ($Protocol -eq "UDP") { "Listening" } else { $Connection.State }
        
        # Get process information
        $processName = "Unknown"
        $processPath = "Unknown"
        $processUser = "Unknown"
        $signatureStatus = "Unknown"
        
        if ($processId) {
            try {
                if ($processId -eq 0) {
                    $processName = "Idle"
                    $processPath = "System Idle Process"
                    $processUser = "SYSTEM"
                    $signatureStatus = "N/A"
                }
                elseif ($processId -eq 4) {
                    $processName = "System"
                    $processPath = "NT Kernel & System"
                    $processUser = "SYSTEM"
                    $signatureStatus = "N/A"
                }
                else {
                    $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
                    if ($process) {
                        $processName = $process.Name
                        $processPath = Get-ProcessExecutablePath -ProcessId $processId
                        $processUser = Get-ProcessUser -ProcessId $processId
                        $signatureStatus = Get-ProcessSignatureStatus -Path $processPath
                    }
                }
            }
            catch {
                Write-Verbose "Could not get full process info for PID $processId"
            }
        }
        
        # Get service information
        $serviceInfo = Get-PortServiceMapping -ProcessId $processId -Port $localPort
        
        # Get port knowledge from database
        $portKnowledge = Get-PortKnowledge -Port $localPort
        
        # Assess risk based on multiple factors
        $riskAssessment = Get-PortRiskAssessment -Port $localPort -LocalAddress $localAddress `
                                                   -ProcessPath $processPath -SignatureStatus $signatureStatus `
                                                   -ServiceInfo $serviceInfo
        
        # Determine binding scope
        $bindingScope = switch ($localAddress) {
            "0.0.0.0" { "All Interfaces (Public)" }
            "::" { "All IPv6 Interfaces (Public)" }
            "127.0.0.1" { "Localhost Only (Private)" }
            "::1" { "Localhost IPv6 Only (Private)" }
            default { "Specific Interface ($localAddress)" }
        }
        
        # Build the intelligence object
        $intelligence = [PSCustomObject]@{
            PSTypeName = "PortIntelligence"
            LocalPort = $localPort
            Protocol = $Protocol
            State = $state
            ProcessId = $processId
            ProcessName = $processName
            ProcessPath = $processPath
            ProcessUser = $processUser
            SignatureStatus = $signatureStatus
            ServiceName = $serviceInfo.ServiceName
            ServiceDisplayName = $serviceInfo.DisplayName
            ServiceBinaryPath = $serviceInfo.BinaryPath
            PortName = $portKnowledge.Name
            Category = $portKnowledge.Category
            Purpose = $portKnowledge.Purpose
            Risk = $riskAssessment.Risk
            RiskReason = $riskAssessment.Reason
            Recommendation = $portKnowledge.Recommendation
            LocalAddress = $localAddress
            BindingScope = $bindingScope
            IsKnownPort = ($localPort -le 1024)
            IsWindowsNative = ($portKnowledge.Category -eq "Windows Native")
            IsSuspicious = $riskAssessment.IsSuspicious
            RemoteAddress = if ($Protocol -eq "TCP") { $Connection.RemoteAddress } else { "N/A" }
            RemotePort = if ($Protocol -eq "TCP") { $Connection.RemotePort } else { 0 }
            Timestamp = Get-Date
        }
        
        return $intelligence
    }
    catch {
        Write-Verbose "Error building intelligence object: $_"
        return $null
    }
}

Export-ModuleMember -Function Get-PortIntelligence
