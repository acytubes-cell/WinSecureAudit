# Validation record

2026-10-04: 38 assertions passed using the available PowerShell 7 runtime on Linux.
Tests are dependency-free and replace Windows collectors inside a temporary module
scope. No real Windows settings are changed or collected by the test suite.

Covered: 12 unique controls; firewall profile binding and ActiveStore; secure and
insecure responses; Defender alternative-AV warning; RDP/NLA; encryption in progress;
SMB enabled/pending/removal-helper states; absent policy; missing Guest; null boot
result; terminating and nonterminating errors; no raw exception leakage; empty,
singleton and all-unknown summaries; coverage math; HTML escaping; synthetic labels;
JSON round trip; HTML output and unique filenames.

Not yet validated: Windows PowerShell 5.1 execution, native cmdlet availability,
actual Windows registry and enum values, elevation behavior, real endpoint reports,
or browser rendering across Windows browsers. Do not describe this as production
validated or Microsoft-baseline compliant.

## Windows acceptance checklist

- Run tests in Windows PowerShell 5.1; expect 38 assertions.
- Run scanner elevated; confirm 12 results and both report files.
- Compare selected findings with Windows Security and your configured policies.
- Open HTML and verify counts match JSON and console.
- Optionally run unelevated; inaccessible checks should be UNKNOWN.
- Record OS version, shell version and unexpected control/error IDs.

No intentionally weakened security settings are required for these steps.

## First user-run Windows scan

2026-10-04: supplied v0.1.1 report confirms an elevated Windows 10 Pro
(build 19045) scan completed 12 controls with no UNKNOWN results. This establishes
one successful live run, not correctness of every finding or broad compatibility.
The report does not record PowerShell version. Real endpoint reports are excluded
from the public source package. The 38-assertion suite was not rerun during
publication preparation because the previous temporary PowerShell runtime was
no longer available; source and tests match the previously tested version.
