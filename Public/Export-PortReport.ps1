<#
.SYNOPSIS
Exports port intelligence data to various formats.

.DESCRIPTION
Exports the results of port intelligence analysis to JSON, CSV, HTML, or console formats.
Supports filtering and customization of output.

.PARAMETER PortData
Array of port intelligence objects to export.

.PARAMETER Format
Output format: JSON, CSV, HTML, or Console.

.PARAMETER OutputPath
Path where the exported file should be saved.

.PARAMETER IncludeTimestamp
Include timestamp in filename.

.PARAMETER OpenAfterExport
Open the file after export (HTML only).

.EXAMPLE
Get-PortIntelligence | Export-PortReport -Format HTML -OutputPath "C:\Reports\ports.html"
Exports to HTML format.

.EXAMPLE
Get-PortIntelligence -RiskLevel Critical,High | Export-PortReport -Format JSON -OutputPath ".\high-risk-ports.json"
Exports only high-risk ports to JSON.

.EXAMPLE
Get-PortIntelligence | Export-PortReport -Format CSV -IncludeTimestamp
Exports to CSV with timestamp in filename.
#>
function Export-PortReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object[]]$PortData,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("JSON", "CSV", "HTML", "Console")]
        [string]$Format,
        
        [string]$OutputPath,
        [switch]$IncludeTimestamp,
        [switch]$OpenAfterExport
    )
    
    begin {
        $allData = @()
    }
    
    process {
        $allData += $PortData
    }
    
    end {
        try {
            if ($allData.Count -eq 0) {
                Write-PortIntelligenceLog "No port data to export." -Level Warning
                return
            }
            
            # Generate filename with timestamp if needed
            if ($IncludeTimestamp -and $OutputPath) {
                $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
                $extension = [System.IO.Path]::GetExtension($OutputPath)
                $baseName = [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)
                $directory = [System.IO.Path]::GetDirectoryName($OutputPath)
                $OutputPath = Join-Path $directory "${baseName}-${timestamp}${extension}"
            }
            
            switch ($Format) {
                "JSON" {
                    Export-PortReportJSON -PortData $allData -OutputPath $OutputPath
                }
                "CSV" {
                    Export-PortReportCSV -PortData $allData -OutputPath $OutputPath
                }
                "HTML" {
                    Export-PortReportHTML -PortData $allData -OutputPath $OutputPath -OpenAfter:$OpenAfterExport
                }
                "Console" {
                    Export-PortReportConsole -PortData $allData
                }
            }
            
            if ($OutputPath -and (Test-Path $OutputPath)) {
                Write-PortIntelligenceLog "Report exported to: $OutputPath" -Level Success
            }
        }
        catch {
            Write-PortIntelligenceLog "Error exporting report: $_" -Level Error
            throw
        }
    }
}

function Export-PortReportJSON {
    param($PortData, $OutputPath)
    
    $jsonData = $PortData | ConvertTo-Json -Depth 10
    
    if ($OutputPath) {
        $jsonData | Out-File -FilePath $OutputPath -Encoding UTF8
    }
    else {
        return $jsonData
    }
}

function Export-PortReportCSV {
    param($PortData, $OutputPath)
    
    # Select relevant columns for CSV
    $csvData = $PortData | Select-Object LocalPort, Protocol, State, ProcessName, ProcessId, `
                                          ServiceName, Category, Risk, Purpose, BindingScope, `
                                          LocalAddress, ProcessUser, SignatureStatus, Recommendation
    
    if ($OutputPath) {
        $csvData | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    }
    else {
        return ($csvData | ConvertTo-Csv -NoTypeInformation)
    }
}

function Export-PortReportHTML {
    param($PortData, $OutputPath, [switch]$OpenAfter)
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Port Intelligence Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; }
        .header h1 { font-size: 28px; margin-bottom: 10px; }
        .header p { opacity: 0.9; font-size: 14px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 30px; background: #f8f9fa; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); border-left: 4px solid; }
        .stat-card.critical { border-left-color: #dc3545; }
        .stat-card.high { border-left-color: #fd7e14; }
        .stat-card.medium { border-left-color: #ffc107; }
        .stat-card.low { border-left-color: #28a745; }
        .stat-card h3 { font-size: 32px; color: #333; margin-bottom: 5px; }
        .stat-card p { color: #666; font-size: 14px; }
        .content { padding: 30px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        thead { background: #f8f9fa; }
        th { padding: 12px; text-align: left; font-weight: 600; color: #333; border-bottom: 2px solid #dee2e6; }
        td { padding: 12px; border-bottom: 1px solid #dee2e6; }
        tr:hover { background: #f8f9fa; }
        .risk-badge { display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600; }
        .risk-critical { background: #dc3545; color: white; }
        .risk-high { background: #fd7e14; color: white; }
        .risk-medium { background: #ffc107; color: #333; }
        .risk-low { background: #28a745; color: white; }
        .risk-unknown { background: #6c757d; color: white; }
        .port-name { font-weight: 600; color: #667eea; }
        .process-info { color: #666; font-size: 13px; }
        .binding { font-family: 'Courier New', monospace; font-size: 12px; color: #666; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 13px; border-top: 1px solid #dee2e6; }
        .suspicious { background: #fff3cd !important; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Port Intelligence Report</h1>
            <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Total Ports: $($PortData.Count)</p>
        </div>
        
        <div class="stats">
            <div class="stat-card critical">
                <h3>$(@($PortData | Where-Object {$_.Risk -eq 'Critical'}).Count)</h3>
                <p>Critical Risk</p>
            </div>
            <div class="stat-card high">
                <h3>$(@($PortData | Where-Object {$_.Risk -eq 'High'}).Count)</h3>
                <p>High Risk</p>
            </div>
            <div class="stat-card medium">
                <h3>$(@($PortData | Where-Object {$_.Risk -eq 'Medium'}).Count)</h3>
                <p>Medium Risk</p>
            </div>
            <div class="stat-card low">
                <h3>$(@($PortData | Where-Object {$_.Risk -eq 'Low'}).Count)</h3>
                <p>Low Risk</p>
            </div>
        </div>
        
        <div class="content">
            <h2 style="margin-bottom: 20px;">Port Details</h2>
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>Service</th>
                        <th>Process</th>
                        <th>Binding</th>
                        <th>Risk</th>
                        <th>Purpose</th>
                    </tr>
                </thead>
                <tbody>
"@
    
    foreach ($port in $PortData) {
        $riskClass = $port.Risk.ToLower()
        $rowClass = if ($port.IsSuspicious) { "suspicious" } else { "" }
        $suspiciousFlag = if ($port.IsSuspicious) { "⚠️ " } else { "" }
        
        $html += @"
                    <tr class="$rowClass">
                        <td><span class="port-name">$($port.LocalPort)</span></td>
                        <td>$($port.Protocol)</td>
                        <td>
                            <strong>$($port.PortName)</strong><br>
                            <span class="process-info">$($port.Category)</span>
                        </td>
                        <td>
                            <strong>$($port.ProcessName)</strong> (PID: $($port.ProcessId))<br>
                            <span class="process-info">$($port.ProcessUser)</span>
                        </td>
                        <td><span class="binding">$($port.BindingScope)</span></td>
                        <td><span class="risk-badge risk-$riskClass">$suspiciousFlag$($port.Risk)</span></td>
                        <td style="font-size: 13px; max-width: 300px;">$($port.Purpose)</td>
                    </tr>
"@
    }
    
    $html += @"
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>Port Intelligence Analyzer - Enterprise Security Tool</p>
        </div>
    </div>
</body>
</html>
"@
    
    if ($OutputPath) {
        $html | Out-File -FilePath $OutputPath -Encoding UTF8
        
        if ($OpenAfter) {
            Start-Process $OutputPath
        }
    }
    else {
        return $html
    }
}

function Export-PortReportConsole {
    param($PortData)
    
    Write-Host ""
    Write-Host ("=" * 87) -ForegroundColor Cyan
    Write-Host "                           PORT INTELLIGENCE REPORT" -ForegroundColor Cyan
    Write-Host ("=" * 87) -ForegroundColor Cyan
    Write-Host "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  |  Total Ports: $($PortData.Count)" -ForegroundColor Gray
    Write-Host ""
    
    # Summary statistics
    $critical = @($PortData | Where-Object {$_.Risk -eq 'Critical'}).Count
    $high = @($PortData | Where-Object {$_.Risk -eq 'High'}).Count
    $medium = @($PortData | Where-Object {$_.Risk -eq 'Medium'}).Count
    $low = @($PortData | Where-Object {$_.Risk -eq 'Low'}).Count
    $suspicious = @($PortData | Where-Object {$_.IsSuspicious}).Count
    
    Write-Host "RISK SUMMARY:" -ForegroundColor Yellow
    Write-Host "  [!] Critical: " -NoNewline; Write-Host $critical -ForegroundColor Red
    Write-Host "  [H] High: " -NoNewline; Write-Host $high -ForegroundColor DarkRed
    Write-Host "  [M] Medium: " -NoNewline; Write-Host $medium -ForegroundColor Yellow
    Write-Host "  [L] Low: " -NoNewline; Write-Host $low -ForegroundColor Green
    if ($suspicious -gt 0) {
        Write-Host "  [!] Suspicious: " -NoNewline; Write-Host $suspicious -ForegroundColor Magenta
    }
    Write-Host ""
    
    # Detailed port listing
    Write-Host "DETAILED PORT ANALYSIS:" -ForegroundColor Yellow
    Write-Host ("-" * 135) -ForegroundColor Gray
    Write-Host ("{0,-6} {1,-8} {2,-12} {3,-8} {4,-25} {5,-30} {6,-10}" -f "Port", "Proto", "State", "PID", "Process", "Service/Binary", "Risk") -ForegroundColor Cyan
    Write-Host ("-" * 135) -ForegroundColor Gray
    
    foreach ($port in $PortData) {
        $riskEmoji = Get-RiskEmoji -Risk $port.Risk
        $riskColor = Get-ColorForRisk -Risk $port.Risk
        $suspiciousFlag = if ($port.IsSuspicious) { "[!] " } else { "    " }
        
        $serviceName = if ($port.ServiceName) { $port.ServiceName } else { $port.PortName }
        if ($serviceName.Length -gt 28) { $serviceName = $serviceName.Substring(0, 25) + "..." }
        
        $processDisplay = $port.ProcessName
        if ($processDisplay.Length -gt 23) { $processDisplay = $processDisplay.Substring(0, 20) + "..." }
        
        Write-Host ("{0,-6} {1,-8} {2,-12} {3,-8} {4,-25} {5,-30}" -f `
            $port.LocalPort, 
            $port.Protocol, 
            $port.State, 
            $port.ProcessId, 
            $processDisplay, 
            $serviceName) -NoNewline
        
        Write-Host " $suspiciousFlag$riskEmoji " -NoNewline
        Write-Host ("{0,-6}" -f $port.Risk) -ForegroundColor $riskColor
        
        # Show purpose on next line
        Write-Host ("        |_ Purpose: {0}" -f $port.Purpose) -ForegroundColor DarkGray
        Write-Host ("        |_ Binding: {0}" -f $port.BindingScope) -ForegroundColor DarkGray
        
        if ($port.IsSuspicious) {
            Write-Host ("        |_ [!] {0}" -f $port.RiskReason) -ForegroundColor Magenta
        }
        Write-Host ""
    }
    
    Write-Host ("=" * 135) -ForegroundColor Cyan
    Write-Host ""
}

Export-ModuleMember -Function Export-PortReport
