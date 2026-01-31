<#
.SYNOPSIS
Maps network ports to their owning Windows services.

.DESCRIPTION
Queries WMI/CIM to match processes to Windows services and retrieve
service details including display name, description, and binary path.

.PARAMETER ProcessId
The process ID to query for service information.

.PARAMETER Port
Optional port number for additional context.

.EXAMPLE
Get-PortServiceMapping -ProcessId 1234
Gets service information for process ID 1234.

.EXAMPLE
Get-PortServiceMapping -ProcessId 1234 -Port 445
Gets service information with port context.
#>
function Get-PortServiceMapping {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$ProcessId,
        
        [int]$Port
    )
    
    try {
        # Handle special system processes
        if ($ProcessId -eq 0) {
            return @{
                ServiceName = "System Idle Process"
                DisplayName = "System Idle Process"
                BinaryPath = "N/A"
                Description = "Represents idle CPU time"
                StartType = "N/A"
                State = "Running"
                IsWindowsService = $false
            }
        }
        
        if ($ProcessId -eq 4) {
            return @{
                ServiceName = "System"
                DisplayName = "NT Kernel & System"
                BinaryPath = "ntoskrnl.exe"
                Description = "Core Windows kernel and system services"
                StartType = "Boot"
                State = "Running"
                IsWindowsService = $true
            }
        }
        
        # Query for service associated with this process
        $service = Get-CimInstance Win32_Service -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
        
        if ($service) {
            # Service found
            return @{
                ServiceName = $service.Name
                DisplayName = $service.DisplayName
                BinaryPath = $service.PathName
                Description = $service.Description
                StartType = $service.StartMode
                State = $service.State
                IsWindowsService = $true
            }
        }
        else {
            # Not a service - it's a standalone process
            $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
            
            if ($process) {
                return @{
                    ServiceName = $null
                    DisplayName = $process.Name
                    BinaryPath = $process.Path
                    Description = "Non-service process"
                    StartType = "N/A"
                    State = "Running"
                    IsWindowsService = $false
                }
            }
            else {
                return @{
                    ServiceName = $null
                    DisplayName = "Unknown"
                    BinaryPath = "Unknown"
                    Description = "Process information unavailable"
                    StartType = "N/A"
                    State = "Unknown"
                    IsWindowsService = $false
                }
            }
        }
    }
    catch {
        Write-Verbose "Error mapping service for PID ${ProcessId}: $_"
        return @{
            ServiceName = $null
            DisplayName = "Error"
            BinaryPath = "Error"
            Description = "Failed to retrieve service information"
            StartType = "N/A"
            State = "Unknown"
            IsWindowsService = $false
        }
    }
}

Export-ModuleMember -Function Get-PortServiceMapping
