# AchieverWinSecureAudit v0.1.1

A learning and portfolio project for read-only Windows endpoint configuration assessment.
Collects 12 findings and writes local HTML and JSON reports. No remediation, uploads,
software installation or recovery-key collection. Windows components may write their
normal diagnostic logs while queried; read-only means no security configuration changes.

**Status:** 38 simulated assertions previously passed on PowerShell 7/Linux. A user-run
scan on Windows 10 Pro (build 19045) completed all 12 controls with no UNKNOWN
results. Individual findings and Windows PowerShell 5.1 tests still need independent
verification; the scan report does not record the shell version. This is not a compliance
certification, Microsoft Secure Score or an implemented Microsoft security baseline.

# Start here

Read [the setup guide](docs/GETTING-STARTED.md). Target: a 64-bit Windows workstation
with 64-bit Windows PowerShell 5.1. Start with your own test PC. Windows Server,
domain controllers and PowerShell 7 live collection are not validated targets.
Unsupported features or insufficient permissions should produce UNKNOWN.

```powershell
.\src\WinSecureAudit.ps1 -OmitComputerName
```

Open the HTML path printed at completion. JSON contains the same structured results.
The `reports` folder is the default destination. Override it with `-OutputDirectory`.
`-OmitComputerName` removes the computer name from report metadata; it is not a
promise of comprehensive anonymisation. Review any report before sharing it.

# What is being checked / Wetin e dey check

| ID            | Condition                                                                |
|---------------|--------------------------------------------------------------------------|
| WSA-DEF-001   | Defender real-time protection; alternatives require review               |
| WSA-FW-DOMAIN / PRIVATE / PUBLIC | Each effective firewall profile in ActiveStore        |
| WSA-BL-001    | OS volume encryption and BitLocker protection                            |
| WSA-BOOT-001  | Secure Boot reading                                                      |
| WSA-SMB-001   | SMBv1 server configuration                                               |
| WSA-SMB-002   | SMBv1 protocol/client/server optional components                         |
| WSA-UAC-001   | EnableLUA only                                                           |
| WSA-GUEST-001 | Local built-in Guest identified by SID suffix -501                       |
| WSA-RDP-001   | RDP and NLA registry configuration, policy before local                  |
| WSA-LOG-001   | Windows PowerShell machine Script Block Logging policy                   |

PASS means the specific condition is met, WARN needs review, FAIL means it is
not met, UNKNOWN means the scanner cannot establish it. A PASS does not certify
the whole computer. Severity is the potential impact of a deficient control;
a PASS can therefore have High severity.

Pass rate = PASS / (PASS + WARN + FAIL). Coverage = assessed / all checks.
For example, 3 PASS and 9 UNKNOWN gives 100% pass rate but only 25% coverage.
No assessed results produces an unavailable pass rate, not a perfect score.

## Learn the code

1. `src/WinSecureAudit.ps1` checks the environment, starts collection and exports reports.
2. `src/WinSecureAudit.psm1` defines each control and its collector (Probe).
3. `Invoke-WSAAudit` catches collector failures independently and returns UNKNOWN.
4. `New-WSAReport` calculates the summary; `ConvertTo-WSAHtml` escapes text for HTML.
5. `Export-WSAReport` writes the two files. It never changes security settings.

Tests use simulated commands so you can learn failure handling without disabling
protection on a real PC:

```powershell
powershell.exe -NoProfile -File .\tests\Run-Tests.ps1
```

See [validation](docs/VALIDATION.md), [changes](CHANGELOG.md), and the synthetic
sample under `reports`. Keep real reports out of GitHub; `.gitignore` excludes them.
A license has not been selected; choose one before distributing this as open source.
