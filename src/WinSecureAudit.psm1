#Requires -Version 5.1
Set-StrictMode -Version Latest

function New-WSAObservation {
    param([ValidateSet('PASS','WARN','FAIL')][string]$Status, [string]$Evidence)
    [pscustomobject]@{ Status = $Status; Evidence = $Evidence }
}

function Get-WSARequiredValue {
    param($InputObject, [string]$Name)
    if ($null -eq $InputObject) { throw 'The collector returned no data.' }
    $p = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $p -or $null -eq $p.Value) { throw "Required property '$Name' is unavailable." }
    $p.Value
}

function Get-WSARegistryValue {
    param([string]$Path, [string]$Name, [switch]$AllowMissing)
    # Open HKLM explicitly in the 64-bit view. Missing policy is different from
    # access denied: only a genuinely missing key/value may return null.
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)
    $key = $null
    try {
        $key = $base.OpenSubKey($Path, $false)
        if ($null -eq $key) {
            if ($AllowMissing) { return $null }
            throw "Required registry key '$Path' is missing."
        }
        $value = $key.GetValue($Name, $null)
        if ($null -eq $value -and -not $AllowMissing) { throw "Required registry value '$Name' is missing." }
        return $value
    } finally {
        if ($null -ne $key) { $key.Dispose() }
        $base.Dispose()
    }
}

function Get-WSAControlDefinitions {
    @(
        @{ Id='WSA-DEF-001'; Control='Defender real-time protection'; Severity='High'; Recommendation='Verify active protection from Defender or an approved alternative. This check does not assess third-party antivirus health.'; Probe={
            $d = Get-MpComputerStatus -ErrorAction Stop
            $v = Get-WSARequiredValue $d 'RealTimeProtectionEnabled'
            if ($v -eq $true) { New-WSAObservation PASS 'Defender reports real-time protection enabled.' }
            elseif ($v -eq $false) { New-WSAObservation WARN 'Defender reports real-time protection disabled; alternative protection is not assessed.' }
            else { throw 'Unexpected Defender protection state.' }
        }}
        foreach ($profileName in @('Domain','Private','Public')) {
            @{ Id="WSA-FW-$($profileName.ToUpperInvariant())"; Control="Firewall: $profileName"; Severity='High'; Recommendation='Review the effective Windows Firewall profile and enable it through your approved management process.'; Arguments=@($profileName); Probe={
                param($profileName)
                $p = @(Get-NetFirewallProfile -Name $profileName -PolicyStore ActiveStore -ErrorAction Stop)
                if ($p.Count -ne 1) { throw 'Expected one effective firewall profile.' }
                $v = [string](Get-WSARequiredValue $p[0] 'Enabled')
                if ($v -in @('True','1')) { New-WSAObservation PASS "$profileName profile enabled in ActiveStore." }
                elseif ($v -in @('False','0')) { New-WSAObservation FAIL "$profileName profile disabled in ActiveStore." }
                else { throw "Unresolved firewall state: $v" }
            } }
        }
        @{ Id='WSA-BL-001'; Control='BitLocker: OS volume'; Severity='High'; Recommendation='Review encryption and protection state. Before planned changes, confirm recovery-key escrow and compatibility. No recovery keys are collected.'; Probe={
            $b = @(Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop)
            if ($b.Count -ne 1) { throw 'Expected one OS volume.' }
            $protection = [string](Get-WSARequiredValue $b[0] 'ProtectionStatus')
            $volume = [string](Get-WSARequiredValue $b[0] 'VolumeStatus')
            $e = "OS volume: ProtectionStatus=$protection; VolumeStatus=$volume."
            if ($protection -eq 'On' -and $volume -eq 'FullyEncrypted') { New-WSAObservation PASS $e }
            elseif ($volume -eq 'EncryptionInProgress') { New-WSAObservation WARN "$e Encryption is not complete." }
            elseif ($protection -eq 'Off' -or $volume -in @('FullyDecrypted','DecryptionInProgress','DecryptionPaused')) { New-WSAObservation FAIL $e }
            elseif ($volume -eq 'EncryptionPaused') { New-WSAObservation WARN $e }
            else { throw "Unresolved BitLocker state. $e" }
        }}
        @{ Id='WSA-BOOT-001'; Control='Secure Boot'; Severity='High'; Recommendation='Review UEFI support and boot compatibility before enabling Secure Boot. Unavailable readings do not prove that it is disabled.'; Probe={
            $v = Confirm-SecureBootUEFI -ErrorAction Stop
            if ($v -eq $true) { New-WSAObservation PASS 'Secure Boot reports enabled.' }
            elseif ($v -eq $false) { New-WSAObservation FAIL 'Secure Boot reports disabled.' }
            else { throw 'No valid Secure Boot result.' }
        }}
        @{ Id='WSA-SMB-001'; Control='SMBv1 server'; Severity='High'; Recommendation='Identify legacy dependencies and plan removal of SMBv1 server support.'; Probe={
            $s = Get-SmbServerConfiguration -ErrorAction Stop
            $v = Get-WSARequiredValue $s 'EnableSMB1Protocol'
            if ($v -eq $false) { New-WSAObservation PASS 'SMBv1 server protocol is disabled; this does not assess the client.' }
            elseif ($v -eq $true) { New-WSAObservation FAIL 'SMBv1 server protocol is enabled.' }
            else { throw 'Unexpected SMB server state.' }
        }}
        @{ Id='WSA-SMB-002'; Control='SMBv1 optional components'; Severity='High'; Recommendation='Review enabled SMBv1 client/server components and pending restarts. Missing feature APIs require manual verification.'; Probe={
            $features = @(Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol*' -ErrorAction Stop | Where-Object { $_.FeatureName -in @('SMB1Protocol','SMB1Protocol-Client','SMB1Protocol-Server') })
            if ($features.Count -eq 0) { throw 'No SMBv1 feature state returned.' }
            $states = @($features | ForEach-Object { [string](Get-WSARequiredValue $_ 'State') })
            $e = ($features | ForEach-Object { '{0}={1}' -f $_.FeatureName, $_.State }) -join '; '
            if (@($states | Where-Object { $_ -eq 'Enabled' }).Count -gt 0) { New-WSAObservation FAIL $e }
            elseif (@($states | Where-Object { $_ -notin @('Disabled','DisabledWithPayloadRemoved','Removed') }).Count -gt 0) { New-WSAObservation WARN "Pending or unresolved feature state: $e" }
            else { New-WSAObservation PASS $e }
        }}
        @{ Id='WSA-UAC-001'; Control='UAC: EnableLUA'; Severity='High'; Recommendation='Review UAC EnableLUA and the broader elevation policy; this check does not validate every UAC setting or pending reboot.'; Probe={
            $v = Get-WSARegistryValue 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
            if ($v -eq 1) { New-WSAObservation PASS 'EnableLUA=1. Other UAC settings are outside this check.' }
            elseif ($v -eq 0) { New-WSAObservation FAIL 'EnableLUA=0.' }
            else { throw 'Unexpected EnableLUA value.' }
        }}
        @{ Id='WSA-GUEST-001'; Control='Built-in local Guest'; Severity='Medium'; Recommendation='Verify the local account with SID suffix -501 and disable it unless there is a documented, approved requirement.'; Probe={
            $guest = @(Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop | Where-Object { $_.SID -match '-501$' })
            if ($guest.Count -ne 1) { throw 'Built-in local Guest could not be uniquely identified.' }
            $v = Get-WSARequiredValue $guest[0] 'Disabled'
            if ($v -eq $true) { New-WSAObservation PASS 'Local account with SID suffix -501 is disabled.' }
            elseif ($v -eq $false) { New-WSAObservation FAIL 'Local account with SID suffix -501 is enabled.' }
            else { throw 'Unexpected Guest account state.' }
        }}
        @{ Id='WSA-RDP-001'; Control='Remote Desktop / NLA'; Severity='High'; Recommendation='Confirm business need, NLA, approved remote access and network restrictions. These registry checks do not prove reachability or effective session behavior.'; Probe={
            $policy = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            $deny = Get-WSARegistryValue $policy 'fDenyTSConnections' -AllowMissing
            $source = 'policy'
            if ($null -eq $deny) { $deny = Get-WSARegistryValue 'SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'; $source = 'local' }
            if ($deny -eq 1) { New-WSAObservation PASS "RDP connections denied by $source configuration." }
            elseif ($deny -eq 0) {
                $nla = Get-WSARegistryValue $policy 'UserAuthentication' -AllowMissing
                if ($null -eq $nla) { $nla = Get-WSARegistryValue 'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' }
                if ($nla -eq 1) { New-WSAObservation WARN 'RDP is configured enabled with NLA required. Review exposure and business need.' }
                elseif ($nla -eq 0) { New-WSAObservation FAIL 'RDP is configured enabled without NLA required.' }
                else { throw 'Unexpected NLA value.' }
            } else { throw 'Unexpected RDP deny value.' }
        }}
        @{ Id='WSA-LOG-001'; Control='Windows PowerShell machine logging policy'; Severity='Medium'; Recommendation='Review machine-level Script Block Logging and access/retention for its logs. User policy, PowerShell 7 and actual event generation are outside this check.'; Probe={
            $v = Get-WSARegistryValue 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' -AllowMissing
            if ($v -eq 1) { New-WSAObservation PASS 'Machine policy EnableScriptBlockLogging=1 for Windows PowerShell.' }
            elseif ($null -eq $v) { New-WSAObservation WARN 'Windows PowerShell machine Script Block Logging policy is not configured.' }
            elseif ($v -eq 0) { New-WSAObservation WARN 'Windows PowerShell machine Script Block Logging policy is disabled.' }
            else { throw 'Unexpected script block logging policy value.' }
        }}
    )
}

function Invoke-WSAAudit {
    [CmdletBinding()]
    param()
    foreach ($control in (Get-WSAControlDefinitions)) {
        $status = 'UNKNOWN'; $evidence = ''; $errorId = $null
        try {
            # Native cmdlets use -ErrorAction Stop; this also catches nonterminating
            # errors raised by providers in the probe scope.
            $ErrorActionPreference = 'Stop'
            $arguments = @()
            if ($control.ContainsKey('Arguments')) { $arguments = @($control.Arguments) }
            $observations = @(& $control.Probe @arguments)
            if ($observations.Count -ne 1) { throw 'Expected exactly one observation.' }
            $observation = $observations[0]
            if ($observation.Status -notin @('PASS','WARN','FAIL')) { throw 'Invalid observation status.' }
            $status = $observation.Status
            $evidence = $observation.Evidence
        } catch {
            # Do not export raw exception messages: they can expose machine paths
            # or identifiers. A stable error ID is enough for first-line debugging.
            $errorId = $_.Exception.GetType().Name
            $evidence = 'Unable to establish the setting. Check permissions, feature availability and platform support.'
        }
        [pscustomobject][ordered]@{
            Id=$control.Id; Control=$control.Control; Status=$status
            Severity=$control.Severity; Evidence=$evidence
            Recommendation=$control.Recommendation; ErrorId=$errorId
        }
    }
}

function New-WSAReport {
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Findings, [string]$ComputerName,
          [string]$OperatingSystem, [bool]$IsAdministrator, [switch]$Synthetic)
    $pass = @($Findings | Where-Object Status -eq 'PASS').Count
    $warn = @($Findings | Where-Object Status -eq 'WARN').Count
    $fail = @($Findings | Where-Object Status -eq 'FAIL').Count
    $unknown = @($Findings | Where-Object Status -eq 'UNKNOWN').Count
    $assessed = $pass + $warn + $fail
    $total = $Findings.Count
    if ($assessed + $unknown -ne $total) { throw 'Findings contain invalid statuses.' }
    $rate = $null; $coverage = 0
    if ($assessed -gt 0) { $rate = [math]::Round(100 * $pass / $assessed, 1) }
    if ($total -gt 0) { $coverage = [math]::Round(100 * $assessed / $total, 1) }
    [pscustomobject][ordered]@{
        Tool='WinSecureAudit'; Version='0.1.1'; SchemaVersion='1.0'
        GeneratedUtc=[DateTime]::UtcNow.ToString('o'); Synthetic=[bool]$Synthetic
        ComputerName=$ComputerName; OperatingSystem=$OperatingSystem
        IsAdministrator=$IsAdministrator
        Assessment='Limited local configuration review; not a Microsoft score, full security assessment or compliance certification.'
        Summary=[pscustomobject][ordered]@{Total=$total; Assessed=$assessed; Pass=$pass; Warn=$warn; Fail=$fail; Unknown=$unknown; PassRatePercent=$rate; CoveragePercent=$coverage}
        Findings=@($Findings)
    }
}

function ConvertTo-WSAHtml {
    param($Report)
    function Encode($value) { [System.Net.WebUtility]::HtmlEncode([string]$value) }
    $rows = foreach ($finding in $Report.Findings) {
        '<tr><td><strong>{0}</strong><br><small>{1}</small></td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}<br><small>{6}</small></td></tr>' -f (Encode $finding.Control), (Encode $finding.Id), (Encode $finding.Status), (Encode $finding.Severity), (Encode $finding.Evidence), (Encode $finding.Recommendation), (Encode $finding.ErrorId)
    }
    $rate = 'N/A'
    if ($null -ne $Report.Summary.PassRatePercent) { $rate = "$($Report.Summary.PassRatePercent)%" }
    $sample = ''
    if ($Report.Synthetic) { $sample = '<p class="notice">SYNTHETIC EXAMPLE - this is not a scan of a real computer.</p>' }
    @"
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>WinSecureAudit report</title><style>
body{margin:0;background:#f3f5f8;color:#192b3d;font:15px/1.6 system-ui,sans-serif}
main{max-width:1350px;margin:auto;padding:36px}h1{font-size:34px;margin:0}h2{font-size:21px}
.eyebrow{color:#236b63;font-weight:700;letter-spacing:2px}.meta,small{color:#536477}
.cards{display:flex;gap:16px;flex-wrap:wrap;margin:24px 0}.card{background:white;border:1px solid #dce3e9;border-radius:12px;padding:18px 26px;min-width:130px}.card strong{font-size:28px;display:block}
.notice{background:#fff2d5;padding:14px;border-left:4px solid #b77d0e}.table{overflow:auto;background:#fff;border-radius:12px}
table{border-collapse:collapse;width:100%}th,td{text-align:left;vertical-align:top;padding:15px;border-bottom:1px solid #e1e7ec}th{background:#192b3d;color:white}td:nth-child(2){font-weight:700;white-space:nowrap}td:first-child{min-width:180px}td:nth-child(4),td:nth-child(5){min-width:220px}
@media print{main{padding:0}body{background:white;font-size:10px}.table{overflow:visible}td,th{padding:7px;min-width:0!important}.cards{margin:10px 0}tr{break-inside:avoid}}
</style></head><body><main><div class="eyebrow">ENDPOINT CONFIGURATION REVIEW</div>
<h1>WinSecureAudit <small>v0.1.1</small></h1>$sample
<p class="meta">$(Encode $Report.ComputerName) &middot; $(Encode $Report.OperatingSystem)<br>UTC: $(Encode $Report.GeneratedUtc) &middot; Elevated: $(Encode $Report.IsAdministrator)</p>
<div class="cards"><div class="card">Pass rate<strong>$(Encode $rate)</strong>Assessed controls only</div><div class="card">Coverage<strong>$(Encode $Report.Summary.CoveragePercent)%</strong>Checks with a verdict</div><div class="card">Pass / Warn / Fail<strong>$($Report.Summary.Pass) / $($Report.Summary.Warn) / $($Report.Summary.Fail)</strong></div><div class="card">Unknown<strong>$($Report.Summary.Unknown)</strong>Needs verification</div></div>
<p>$(Encode $Report.Assessment)</p><p>PASS: checked condition met. WARN: review required. FAIL: checked condition not met. UNKNOWN: evidence unavailable. Severity describes potential impact when a control is deficient, including on PASS rows.</p>
<h2>Findings and review guidance</h2><div class="table"><table><thead><tr><th>Control</th><th>Status</th><th>Severity</th><th>Evidence</th><th>Next step / error ID</th></tr></thead><tbody>$($rows -join "`n")</tbody></table></div>
<p class="meta">Local report. No external assets or telemetry. Review findings before making changes.</p></main></body></html>
"@
}

function Export-WSAReport {
    [CmdletBinding()]
    param($Report, [string]$OutputDirectory)
    $directory = [IO.Path]::GetFullPath($OutputDirectory)
    [void][IO.Directory]::CreateDirectory($directory)
    $stem = 'WinSecureAudit-{0}-{1}' -f ([DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')), ([guid]::NewGuid().ToString('N').Substring(0,8))
    $jsonPath = Join-Path $directory "$stem.json"
    $htmlPath = Join-Path $directory "$stem.html"
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($jsonPath, ($Report | ConvertTo-Json -Depth 8), $utf8)
    [IO.File]::WriteAllText($htmlPath, (ConvertTo-WSAHtml $Report), $utf8)
    [pscustomobject]@{Json=$jsonPath; Html=$htmlPath}
}

Export-ModuleMember -Function Invoke-WSAAudit, New-WSAReport, Export-WSAReport, ConvertTo-WSAHtml
