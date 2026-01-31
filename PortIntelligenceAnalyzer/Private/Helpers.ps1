# Helper functions for Port Intelligence Analyzer

function Test-IsAdministrator {
    <#
    .SYNOPSIS
    Checks if the current PowerShell session is running with administrator privileges.
    #>
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ColorForRisk {
    <#
    .SYNOPSIS
    Returns console color based on risk level.
    #>
    param([string]$Risk)
    
    switch ($Risk) {
        "Critical" { return "Red" }
        "High" { return "DarkRed" }
        "Medium" { return "Yellow" }
        "Low" { return "Green" }
        "Unknown" { return "Gray" }
        default { return "White" }
    }
}

function Get-RiskEmoji {
    <#
    .SYNOPSIS
    Returns emoji indicator for risk level.
    #>
    param([string]$Risk)
    
    switch ($Risk) {
        "Critical" { return "[!]" }
        "High" { return "[H]" }
        "Medium" { return "[M]" }
        "Low" { return "[L]" }
        "Unknown" { return "[?]" }
        default { return "[-]" }
    }
}

function Get-ProcessUser {
    <#
    .SYNOPSIS
    Gets the user account running a process.
    #>
    param([int]$ProcessId)
    
    try {
        if ($ProcessId -eq 0 -or $ProcessId -eq 4) {
            return "SYSTEM"
        }
        
        $process = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
        if ($process) {
            $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwner
            if ($owner.Domain -and $owner.User) {
                return "$($owner.Domain)\$($owner.User)"
            }
            elseif ($owner.User) {
                return $owner.User
            }
        }
        return "SYSTEM"
    }
    catch {
        return "Unknown"
    }
}

function Get-ProcessExecutablePath {
    <#
    .SYNOPSIS
    Gets the full path of the executable for a process.
    #>
    param([int]$ProcessId)
    
    try {
        if ($ProcessId -eq 0) {
            return "System Idle Process"
        }
        if ($ProcessId -eq 4) {
            return "NT Kernel and System"
        }
        
        $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($process -and $process.Path) {
            return $process.Path
        }
        
        # Try WMI if Get-Process doesn't work
        $wmiProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
        if ($wmiProcess -and $wmiProcess.ExecutablePath) {
            return $wmiProcess.ExecutablePath
        }
        
        return "Unknown"
    }
    catch {
        return "Unknown"
    }
}

function Get-ProcessSignatureStatus {
    <#
    .SYNOPSIS
    Checks if an executable is digitally signed.
    #>
    param([string]$Path)
    
    try {
        if ($Path -in @("System Idle Process", "NT Kernel and System", "Unknown", "")) {
            return "N/A"
        }
        
        if (-not (Test-Path $Path)) {
            return "Path Not Found"
        }
        
        $signature = Get-AuthenticodeSignature -FilePath $Path -ErrorAction SilentlyContinue
        if ($signature) {
            return $signature.Status.ToString()
        }
        return "Unknown"
    }
    catch {
        return "Error"
    }
}

function Get-ParentProcess {
    <#
    .SYNOPSIS
    Gets the parent process information.
    #>
    param([int]$ProcessId)
    
    try {
        $process = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
        if ($process -and $process.ParentProcessId) {
            $parentProcess = Get-Process -Id $process.ParentProcessId -ErrorAction SilentlyContinue
            if ($parentProcess) {
                return @{
                    Name = $parentProcess.Name
                    Id = $parentProcess.Id
                    Path = $parentProcess.Path
                }
            }
        }
        return $null
    }
    catch {
        return $null
    }
}

function Format-ByteSize {
    <#
    .SYNOPSIS
    Formats byte size to human-readable format.
    #>
    param([long]$Bytes)
    
    if ($Bytes -gt 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -gt 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    if ($Bytes -gt 1KB) { return "{0:N2} KB" -f ($Bytes / 1KB) }
    return "$Bytes B"
}

function Write-PortIntelligenceLog {
    <#
    .SYNOPSIS
    Writes log messages with timestamp.
    #>
    param(
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "Info" { "Cyan" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        "Success" { "Green" }
    }
    
    Write-Host "[$timestamp] " -NoNewline -ForegroundColor Gray
    Write-Host "[$Level] " -NoNewline -ForegroundColor $color
    Write-Host $Message
}

Export-ModuleMember -Function Test-IsAdministrator, Get-ColorForRisk, Get-RiskEmoji, 
                              Get-ProcessUser, Get-ProcessExecutablePath, Get-ProcessSignatureStatus,
                              Get-ParentProcess, Format-ByteSize, Write-PortIntelligenceLog
