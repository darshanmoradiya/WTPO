@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'PortIntelligenceAnalyzer.psm1'

    # Version number of this module.
    ModuleVersion = '1.0.0'

    # Supported PSEditions
    CompatiblePSEditions = @('Desktop', 'Core')

    # ID used to uniquely identify this module
    GUID = '8f4a7d3e-9c2b-4e1f-a6d8-5b3c9e7f2a1d'

    # Author of this module
    Author = 'Port Intelligence Team'

    # Company or vendor of this module
    CompanyName = 'Enterprise Security'

    # Copyright statement for this module
    Copyright = '(c) 2026 Enterprise Security. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'Enterprise-grade port forensics analyzer that explains why ports are open and assesses security posture on Windows systems.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Functions to export from this module
    FunctionsToExport = @(
        'Get-PortIntelligence',
        'Get-PortRiskAssessment',
        'Get-PortServiceMapping',
        'Export-PortReport',
        'Watch-PortChanges',
        'Close-SuspiciousPort'
    )

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            Tags = @('Security', 'Network', 'Port', 'Forensics', 'Windows', 'Monitoring')
            LicenseUri = ''
            ProjectUri = ''
            IconUri = ''
            ReleaseNotes = 'Phase 1 MVP: Port enumeration, process mapping, basic risk categorization, and CLI output'
        }
    }
}
