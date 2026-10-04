#Requires -Version 5.1
# Dependency-free, simulated collectors. No Windows configuration is read/changed.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot '../src/WinSecureAudit.psm1') -Force
$m = Get-Module WinSecureAudit
& $m {
    $script:checks = 0
    function Assert($Condition, $Message) {
        if (-not $Condition) { throw "FAILED: $Message" }
        $script:checks++
    }
    function Get-MpComputerStatus { param($ErrorAction) if ($script:broken) { throw 'SECRET-HOST confidential-path' }; [pscustomobject]@{RealTimeProtectionEnabled=$script:secure} }
    function Get-NetFirewallProfile { param($Name,$PolicyStore,$ErrorAction)
        if ($script:broken) { Write-Error 'SECRET-HOST'; return }
        Assert ($PolicyStore -eq 'ActiveStore') 'Effective firewall store'
        [pscustomobject]@{Enabled=($Name -ne 'Private')}
    }
    function Get-BitLockerVolume { param($MountPoint,$ErrorAction) [pscustomobject]@{ProtectionStatus='On';VolumeStatus=$script:volume} }
    function Confirm-SecureBootUEFI { param($ErrorAction) if ($script:broken) { return }; $script:secure }
    function Get-SmbServerConfiguration { param($ErrorAction) [pscustomobject]@{EnableSMB1Protocol=(-not $script:secure)} }
    # Online is a switch on the real cmdlet.
    function Get-WindowsOptionalFeature { param([switch]$Online,$FeatureName,$ErrorAction)
        [pscustomobject]@{FeatureName='SMB1Protocol-Client';State=$script:feature}
        [pscustomobject]@{FeatureName='SMB1Protocol-Deprecation';State='Enabled'}
    }
    function Get-CimInstance { param($ClassName,$Filter,$ErrorAction)
        if (-not $script:broken) { [pscustomobject]@{SID='S-1-5-21-123-501';Disabled=$script:secure} }
    }
    function Get-WSARegistryValue { param($Path,$Name,[switch]$AllowMissing)
        if ($Name -eq 'fDenyTSConnections') {
            if ($Path -like 'SOFTWARE*') { return $script:deny }
            return 0
        }
        if ($Name -eq 'UserAuthentication') { return $script:nla }
        if ($Name -eq 'EnableScriptBlockLogging') { return $script:logging }
        return [int]$script:secure
    }
    $script:secure=$true; $script:broken=$false; $script:volume='FullyEncrypted'
    $script:feature='Disabled'; $script:deny=1; $script:nla=1; $script:logging=1
    $f=@(Invoke-WSAAudit)
    Assert ($f.Count -eq 12) '12 controls emitted'
    Assert (@($f | Select-Object -ExpandProperty Id -Unique).Count -eq 12) 'Unique IDs'
    Assert (($f | Where-Object Id -eq WSA-FW-DOMAIN).Status -eq 'PASS') 'Domain firewall helper scope'
    Assert (($f | Where-Object Id -eq WSA-FW-PRIVATE).Status -eq 'FAIL') 'Independent private profile'
    Assert (($f | Where-Object Id -eq WSA-FW-PUBLIC).Status -eq 'PASS') 'Independent public profile'
    Assert (@($f | Where-Object Status -eq PASS).Count -eq 11) 'Secure fixture including SMB removal helper'
    $script:secure=$false; $script:deny=0; $script:nla=0; $script:logging=$null
    $script:volume='FullyDecrypted'; $script:feature='Enabled'
    $f=@(Invoke-WSAAudit)
    Assert (($f | Where-Object Id -eq WSA-DEF-001).Status -eq 'WARN') 'Defender disabled requires alternative AV review'
    Assert (($f | Where-Object Id -eq WSA-RDP-001).Status -eq 'FAIL') 'RDP without NLA'
    Assert (($f | Where-Object Id -eq WSA-LOG-001).Status -eq 'WARN') 'Missing logging policy'
    Assert (($f | Where-Object Id -eq WSA-BL-001).Status -eq 'FAIL') 'Decrypted disk'
    Assert (($f | Where-Object Id -eq WSA-SMB-002).Status -eq 'FAIL') 'SMB client enabled'
    $script:volume='EncryptionInProgress'; $script:feature='DisablePending'; $script:nla=1
    $f=@(Invoke-WSAAudit)
    foreach ($id in @('WSA-BL-001','WSA-SMB-002','WSA-RDP-001')) { Assert (($f | Where-Object Id -eq $id).Status -eq 'WARN') "Review $id" }
    $script:broken=$true
    $f=@(Invoke-WSAAudit)
    foreach ($id in @('WSA-DEF-001','WSA-FW-DOMAIN','WSA-BOOT-001','WSA-GUEST-001')) { Assert (($f | Where-Object Id -eq $id).Status -eq 'UNKNOWN') "Unavailable $id" }
    Assert (($f | ConvertTo-Json) -notmatch 'SECRET-HOST') 'No raw exception text exported'
    $fixture=@('PASS','WARN','FAIL','UNKNOWN') | ForEach-Object {
        [pscustomobject]@{Id='DEMO';Control='<script>alert(1)</script>';Status=$_;Severity='High';Evidence='A&B';Recommendation='Review';ErrorId=$null}
    }
    $r=New-WSAReport -Findings $fixture -ComputerName 'SYNTHETIC-PC' -OperatingSystem 'Simulated Windows' -IsAdministrator $false -Synthetic
    Assert ($r.Summary.PassRatePercent -eq 33.3) 'Unknown excluded from pass-rate denominator'
    Assert ($r.Summary.CoveragePercent -eq 75) 'Coverage exposes unknowns'
    $empty=New-WSAReport -Findings @()
    Assert ($null -eq $empty.Summary.PassRatePercent -and $empty.Summary.CoveragePercent -eq 0) 'Empty report'
    $unknown=New-WSAReport -Findings @($fixture[3])
    Assert ($null -eq $unknown.Summary.PassRatePercent) 'All unknown is not 100 percent'
    $one=New-WSAReport -Findings @($fixture[0])
    Assert ($one.Summary.Pass -eq 1) 'Singleton report under strict mode'
    $html=ConvertTo-WSAHtml $r
    Assert ($html -notmatch '<script>' -and $html -match '&lt;script&gt;') 'HTML encoding'
    Assert ($html -match 'SYNTHETIC EXAMPLE') 'Sample clearly labelled'
    $temp=Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
    try {
        $paths=Export-WSAReport $r $temp
        $roundtrip=Get-Content -LiteralPath $paths.Json -Raw | ConvertFrom-Json
        Assert ($roundtrip.Findings.Count -eq 4 -and $roundtrip.Synthetic) 'JSON round trip'
        Assert ((Get-Item -LiteralPath $paths.Html).Length -gt 0) 'HTML export'
        $paths2=Export-WSAReport $r $temp
        Assert ($paths2.Json -ne $paths.Json) 'Unique output filenames'
    } finally { Remove-Item -LiteralPath $temp -Recurse -Force }
    Write-Host "PASS: $script:checks assertions. Simulated collectors only."
}
Remove-Module WinSecureAudit
