<#
.SYNOPSIS
    Sysmon-Generator - Installed Software & Process Inventory Scanner
.DESCRIPTION
    Scans the local Windows machine for installed applications, running processes,
    and services, producing a JSON report compatible with Sysmon-Generator's
    Software Inventory & Rule Suggester.
.OUTPUTS
    software_scan_report.json
#>

[CmdletBinding()]
param(
    [string]$OutputFile = "software_scan_report.json"
)

Write-Host "[+] Running Sysmon-Generator Software Inventory Scanner..." -ForegroundColor Cyan

$results = [ordered]@{
    scanner_version = "1.0.0"
    timestamp = (Get-Date -Format "o")
    os_info = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture)
    installed_software = @()
    running_processes = @()
    services = @()
}

# 1. Query Registry Uninstall Keys (64-bit and 32-bit)
$regPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$installed = Get-ItemProperty $regPaths -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne "" } |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation, UninstallString |
    Sort-Object DisplayName -Unique

foreach ($item in $installed) {
    $results.installed_software += [ordered]@{
        name = $item.DisplayName
        version = $item.DisplayVersion
        publisher = $item.Publisher
        install_location = $item.InstallLocation
    }
}
Write-Host "    Found $($results.installed_software.Count) installed applications." -ForegroundColor Green

# 2. Query Running Processes
$processes = Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $_.Path } |
    Select-Object Name, Path, Company, ProductVersion |
    Sort-Object Name -Unique

foreach ($proc in $processes) {
    $results.running_processes += [ordered]@{
        name = $proc.Name
        path = $proc.Path
        publisher = $proc.Company
        version = $proc.ProductVersion
    }
}
Write-Host "    Found $($results.running_processes.Count) running processes with verified paths." -ForegroundColor Green

# 3. Export JSON
$results | ConvertTo-Json -Depth 4 | Set-Content -Path $OutputFile -Encoding UTF8
Write-Host "[✓] Scan completed! Report saved to: $OutputFile" -ForegroundColor Green
Write-Host "    Import this file into Sysmon-Generator -> Software Scanner tab." -ForegroundColor Cyan
