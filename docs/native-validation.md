# Native event validation components

`native-validation` collects a fixed, benign native Security 4688 process-creation event. Sysmon is out of scope. It is the first executable collector for issue #387; it does not complete every role, event family or Sigma/backend acceptance case.

```powershell
# Read-only prerequisite assessment. No child process or output directory.
./WELA.ps1 native-validation
# Explicitly launch one fixed System32 cmd.exe echo command and collect its event.
./WELA.ps1 native-validation -ProbeAction Run -ProbeOutputPath C:\Lab\evidence\probe-001
```

Use 64-bit elevated Windows PowerShell 5.1 or PowerShell 7 on a reviewed Windows 11 build (22000, 22621, 22631, 26100 or 26200), Server 2022 (20348) or Server 2025 (26100). The collector detects the actual client/member/DC/ADCS context; combined DC+CA hosts and unknown builds remain unsupported. Exact patch, edition, architecture, join state and installed roles must be readable. Policy administration remains a separate operator action: this command does not enable auditing, refresh GPO, change SACLs, clear logs, restart services or contact a backend.

Prerequisites are effective Process Creation Success auditing, DWORD `SCENoApplyLegacyAuditPolicy=1`, DWORD `ProcessCreationIncludeCmdLine_Enabled=1` and an enabled/readable Security channel. Plan reports observed prerequisites only; Run repeats the observations before launch and after collection. A changed audit mask, prerequisite or host context prevents a successful result. Observations do not establish persistence through a later policy refresh.

The two native host readers must agree on build. The reported role, patch, join
state and installed-role summary must also agree with the detailed host
observations; a client/member observation cannot be labeled as a DC, and an AD CS
label additionally requires the installed CA role. Contradictory evidence is
reported as Unverified even if the process event itself matches.

Run launches the Windows system `cmd.exe` with `/d /c echo WELA_PROBE_<random-guid>`; callers cannot supply executable paths or commands. It retains only the single matching event XML, using native provider identity, EventID 4688/version 2, successful-audit keyword, local computer name (or joined FQDN), time window, child PID, creator PID, executable path and complete fixed command line. Duplicate matches, unknown schema, access denial, drift, timeout or a 512-event query cap produce `Unverified` and exit 1. Event polling defaults to 15 seconds and supports `-ProbeTimeoutSeconds 1..30`; each synchronous Windows query can take additional time. The child process has a separate 10-second limit. The collector never exports the entire Security log.

The destination must be a new directory under an existing parent. On Windows, its ACL is restricted to the current user, SYSTEM and local Administrators. Files use CreateNew and cannot overwrite prior evidence. A completed collection contains `before-state.json`, `process.json`, `event.xml`, `after-state.json` and `manifest.json`. The manifest fingerprints each component using SHA-256 and preserves the collector status. Partial artifacts and diagnostics remain available after failure. These hashes detect changes relative to the manifest; they are not signatures or proof against a malicious evidence author. Review and protect the directory before sharing its host/policy metadata.

## Completing rule and backend evidence

`NativeEventObserved` means the fixed probe produced the expected local telemetry in the recorded context and time. `ReadyRuleCredit` always remains zero. The random benign command will ordinarily not satisfy an existing detection rule.

The component bundle is deliberately a different kind from `WelaNativeRuleEvidence` and cannot be supplied directly as a completed readiness bundle. To validate a specific rule, use the [native rule eligibility contract](native-rule-eligibility.md), retain its full original rule, obtain an independent complete normalization review, generate a suitable controlled scenario, and preserve backend ingestion, the translated query and its actual successful result. Do not relabel this probe as a rule match or invent the missing artifacts. A supported native event and state snapshot can inform that lab work; the original component manifest remains the provenance record. No backend name, rule match or query result is manufactured by this command.

## Verification and remaining acceptance

Synthetic tests exercise identity/schema/time/command mismatches, disabled or mistyped prerequisites, drift, caps, denied access, output collisions and public command isolation. They provide no native event evidence. A separate explicitly opted-in GitHub-hosted runner test temporarily enables the three prerequisites, captures a real matching 4688 event on Server 2022/2025 under PowerShell 5.1/7 and restores the exact previous audit mask and registry value kinds/absence in `finally`, verifying restoration. The production collector contains no policy writer. CI does not provision a DC or CA, test Windows 11, forward an event or execute a Sigma query. Those cases remain isolated-lab acceptance work before closing #387.

Microsoft documents the event schema and command-line prerequisite in [4688: A new process has been created](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688). The collector requires the reviewed modern version 2 schema rather than extrapolating from older versions.
