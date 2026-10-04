#Requires -Version 5.1
<#
.SYNOPSIS
Read-only local Windows security configuration assessment.
.DESCRIPTION
Writes HTML and JSON reports only. Does not remediate, upload data, install
software, collect recovery keys, or change execution policy.
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\reports'),
    [switch]$OmitComputerName
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Run this scanner on Windows using 64-bit Windows PowerShell 5.1.' }
if (-not [Environment]::Is64BitProcess) { throw 'Open 64-bit Windows PowerShell, not Windows PowerShell (x86).' }
Import-Module (Join-Path $PSScriptRoot 'WinSecureAudit.psm1') -Force
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} finally { $identity.Dispose() }
if (-not $isAdmin) { Write-Warning 'Not elevated: some checks may be UNKNOWN. No automatic elevation will occur.' }
Write-Host 'WinSecureAudit v0.1.1 | Read-only configuration assessment'
$computerName = $env:COMPUTERNAME
if ($OmitComputerName) { $computerName = 'REDACTED' }
$osInfo = 'Unavailable'
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $osInfo = '{0} (build {1})' -f $os.Caption, $os.BuildNumber
} catch { Write-Warning 'OS metadata could not be read; individual checks will still run.' }
$findings = @(Invoke-WSAAudit)
$report = New-WSAReport -Findings $findings -ComputerName $computerName -OperatingSystem $osInfo -IsAdministrator $isAdmin
$paths = Export-WSAReport -Report $report -OutputDirectory $OutputDirectory
$findings | Format-Table Id, Status, Severity, Control -AutoSize | Out-Host
$s = $report.Summary
Write-Host ('PASS {0} | WARN {1} | FAIL {2} | UNKNOWN {3}' -f $s.Pass, $s.Warn, $s.Fail, $s.Unknown)
if ($null -eq $s.PassRatePercent) { Write-Host 'Pass rate: unavailable (no assessed controls)' }
else { Write-Host ('Pass rate: {0}% of assessed controls' -f $s.PassRatePercent) }
Write-Host ('Coverage: {0}% | This is not a Microsoft score or compliance certification.' -f $s.CoveragePercent)
Write-Host ('HTML: {0}' -f $paths.Html)
Write-Host ('JSON: {0}' -f $paths.Json)
$paths
