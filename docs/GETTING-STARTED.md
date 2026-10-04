# Your first Windows run

## 1. Extract the project

Download the ZIP, right-click it and choose Extract All. Move the inner
`WinSecureAudit` folder to a convenient location such as `C:\Users\YOURNAME\Documents`.
Do not run files directly inside the ZIP. You should see README.md and src,
docs, tests and reports folders. No Python, Git or extra PowerShell modules
need to be installed to begin; unavailable Windows components return UNKNOWN.

## 2. Open the right shell

Search Start for **Windows PowerShell**, choose **Run as administrator** and
approve the Windows prompt. Avoid Windows PowerShell (x86). Elevation lets more
collectors read settings; the scanner still does not change them.

Type `cd ` followed by your extracted folder path in quotes, for example:

```powershell
cd "C:\Users\YOURNAME\Documents\WinSecureAudit"
$PSVersionTable.PSVersion
[Environment]::Is64BitProcess
Get-ChildItem
```

Replace YOURNAME with your Windows profile folder. Expect version 5.1, True,
and a listing containing src. If your location differs, use that actual path.

## 3. Allow this reviewed project to run in this session

Review the two source files in Notepad first. On your own PC:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Confirm if prompted. This affects only the current PowerShell session, not a
permanent machine setting. Organisation Group Policy can override it; if managed
policy blocks execution, use your IT team's approved process rather than trying
to defeat the policy. Closing this PowerShell window ends the session setting.

## 4. Run the audit

```powershell
.\src\WinSecureAudit.ps1 -OmitComputerName
```

Wait for the table, counts and HTML/JSON paths. Optional component queries may
be slower than the other checks. The command runs locally and does not upload
the results. There are 12 controls. Warnings and UNKNOWN results are valid
outcomes, not proof the script crashed.

## 5. Read your report

Open the `reports` folder and double-click the newest HTML file. The bundled
`sample-report.html` is synthetic; your scan has a timestamp and unique suffix.
HTML is for reading; JSON is for automation and later comparisons.

Read FAIL findings, then WARN and UNKNOWN. Check the evidence before deciding
on any configuration changes. For example, Defender off may mean another
antivirus is active, while UNKNOWN BitLocker may mean the API is unavailable.

## 6. Bring the results back

Share the console table and summary, or review and attach the generated JSON.
Do not send recovery keys, credentials or unrelated personal data. We will use
these findings to verify the collectors before extending the project.

## Troubleshooting

| Symptom                              | What to do                                        |
|--------------------------------------|---------------------------------------------------|
|1. Script path not found              | Use Get-ChildItem; navigate to the folder containing src |
|2. Scripts disabled                   | Check Get-ExecutionPolicy -List; follow step 3 if permitted |
|3. File still blocked after reviewing | On your own PC, review and unblock each source file through File Properties if needed |
|4. Many UNKNOWN findings              | Confirm elevation and Windows PowerShell 5.1; share control IDs and error IDs |
|5. BitLocker UNKNOWN                  | Check edition/API availability and permissions; do not infer disk state |
|6. Report write access denied         | Add -OutputDirectory "$env:USERPROFILE\Documents\WSA-Reports" |
|7. Red terminating error              | Copy the error and command used; omit sensitive paths if necessary |

## Why this is useful learning

Collection answers 'what does Windows report?' Evaluation answers 'does that
meet this check?' Reporting records evidence and uncertainty. Keeping these
separate prevents a missing reading from becoming a misleading PASS or FAIL.

Microsoft references:
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies
- https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile
- https://learn.microsoft.com/en-us/powershell/module/dism/get-windowsoptionalfeature
