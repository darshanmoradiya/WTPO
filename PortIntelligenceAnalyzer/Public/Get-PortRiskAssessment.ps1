<#
.SYNOPSIS
Assesses the security risk of an open network port.

.DESCRIPTION
Analyzes multiple factors to determine the security risk level of an open port:
- Port number and known vulnerabilities
- Network binding scope (all interfaces vs localhost)
- Process signature status
- Service type (Windows native vs third-party)
- Port exposure patterns

.PARAMETER Port
The port number to assess.

.PARAMETER LocalAddress
The local IP address the port is bound to.

.PARAMETER ProcessPath
Full path to the process executable.

.PARAMETER SignatureStatus
Digital signature status of the executable.

.PARAMETER ServiceInfo
Service information object from Get-PortServiceMapping.

.EXAMPLE
Get-PortRiskAssessment -Port 445 -LocalAddress "0.0.0.0"
Assesses risk for SMB port exposed on all interfaces.

.EXAMPLE
Get-PortRiskAssessment -Port 8080 -LocalAddress "127.0.0.1" -ProcessPath "C:\app\server.exe"
Assesses risk for custom port bound to localhost.
#>
function Get-PortRiskAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port,
        
        [string]$LocalAddress = "0.0.0.0",
        [string]$ProcessPath = "",
        [string]$SignatureStatus = "Unknown",
        [hashtable]$ServiceInfo = @{}
    )
    
    try {
        # Get base risk from port knowledge database
        $portKnowledge = Get-PortKnowledge -Port $Port
        $baseRisk = $portKnowledge.Risk
        
        # Initialize risk assessment
        $riskFactors = @()
        $finalRisk = $baseRisk
        $isSuspicious = $false
        
        # Factor 1: Network exposure
        $isPubliclyExposed = $LocalAddress -in @("0.0.0.0", "::")
        $isLocalhost = $LocalAddress -in @("127.0.0.1", "::1")
        
        if ($isPubliclyExposed) {
            # Escalate risk for publicly exposed ports
            if ($baseRisk -eq "Medium") {
                $finalRisk = "High"
                $riskFactors += "Exposed to all network interfaces"
            }
            elseif ($baseRisk -eq "High") {
                $finalRisk = "Critical"
                $riskFactors += "Critical service exposed to all interfaces"
            }
            elseif ($baseRisk -eq "Unknown" -and $Port -gt 1024) {
                $riskFactors += "Unknown service exposed publicly"
                $isSuspicious = $true
            }
        }
        elseif ($isLocalhost) {
            # Reduce risk for localhost-only bindings
            if ($baseRisk -eq "High") {
                $finalRisk = "Medium"
                $riskFactors += "Bound to localhost only (reduced risk)"
            }
            elseif ($baseRisk -eq "Critical") {
                $finalRisk = "High"
                $riskFactors += "Critical service on localhost (contained)"
            }
        }
        
        # Factor 2: Process signature status
        if ($SignatureStatus -notin @("Valid", "N/A", "Unknown")) {
            $isSuspicious = $true
            $riskFactors += "Process not properly signed ($SignatureStatus)"
            
            # Escalate risk for unsigned binaries
            if ($finalRisk -eq "Unknown") {
                $finalRisk = "Medium"
            }
        }
        
        # Factor 3: Non-service process detection
        if ($ServiceInfo -and -not $ServiceInfo.IsWindowsService) {
            # Check if it's a known development tool
            $devProcesses = @("node.exe", "python.exe", "java.exe", "dotnet.exe", "code.exe", "devenv.exe")
            $processName = [System.IO.Path]::GetFileName($ProcessPath)
            
            if ($processName -in $devProcesses) {
                $riskFactors += "Development process (review necessity)"
            }
            else {
                if ($Port -gt 10000 -or ($Port -gt 1024 -and $Port -lt 5000)) {
                    $riskFactors += "Non-service process on custom port"
                    $isSuspicious = $true
                }
            }
        }
        
        # Factor 4: Well-known dangerous ports
        $criticalPorts = @(135, 139, 445, 3389, 23)
        if ($Port -in $criticalPorts -and $isPubliclyExposed) {
            $finalRisk = "Critical"
            $riskFactors += "High-value target for attackers"
        }
        
        # Factor 5: Multiple suspicious factors
        if ($isSuspicious -and $riskFactors.Count -ge 2) {
            if ($finalRisk -eq "Unknown") {
                $finalRisk = "High"
            }
            elseif ($finalRisk -eq "Low") {
                $finalRisk = "Medium"
            }
        }
        
        # Factor 6: Outdated protocols
        $legacyPorts = @(21, 23, 80, 25)
        if ($Port -in $legacyPorts -and $isPubliclyExposed) {
            $riskFactors += "Outdated/unencrypted protocol"
        }
        
        # Factor 7: Database ports exposed publicly
        $databasePorts = @(1433, 3306, 5432, 27017, 6379)
        if ($Port -in $databasePorts -and $isPubliclyExposed) {
            $riskFactors += "Database port exposed to network"
            if ($finalRisk -eq "Medium") {
                $finalRisk = "High"
            }
        }
        
        # Build comprehensive reason
        $reason = if ($riskFactors.Count -gt 0) {
            $riskFactors -join "; "
        }
        else {
            "Standard configuration"
        }
        
        return @{
            Risk = $finalRisk
            Reason = $reason
            IsSuspicious = $isSuspicious
            RiskFactors = $riskFactors
            BaseRisk = $baseRisk
            IsPubliclyExposed = $isPubliclyExposed
        }
    }
    catch {
        Write-Verbose "Error assessing risk: $_"
        return @{
            Risk = "Unknown"
            Reason = "Error during risk assessment"
            IsSuspicious = $true
            RiskFactors = @()
            BaseRisk = "Unknown"
            IsPubliclyExposed = $false
        }
    }
}

Export-ModuleMember -Function Get-PortRiskAssessment
