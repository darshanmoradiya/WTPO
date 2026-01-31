#
# Module manifest for PortIntelligenceAnalyzer
# Enterprise-grade port forensics analyzer for Windows systems
#

# Import helper functions
. $PSScriptRoot\Private\Helpers.ps1
. $PSScriptRoot\Private\PortDatabase.ps1

# Import public functions
. $PSScriptRoot\Public\Get-PortIntelligence.ps1
. $PSScriptRoot\Public\Get-PortServiceMapping.ps1
. $PSScriptRoot\Public\Get-PortRiskAssessment.ps1
. $PSScriptRoot\Public\Export-PortReport.ps1
. $PSScriptRoot\Public\Watch-PortChanges.ps1
. $PSScriptRoot\Public\Close-SuspiciousPort.ps1

# Module initialization
Write-Verbose "Port Intelligence Analyzer module loaded successfully"

# Export module members
Export-ModuleMember -Function @(
    'Get-PortIntelligence',
    'Get-PortServiceMapping',
    'Get-PortRiskAssessment',
    'Export-PortReport',
    'Watch-PortChanges',
    'Close-SuspiciousPort'
)
