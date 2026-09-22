# Native Security 4703 audit attribution

The disposable `Native Security 4703 audit attribution` workflow tests the two historical audit-subcategory candidates for event 4703 on standalone Windows Server 2022/2025 under Windows PowerShell 5.1 and PowerShell 7. It does not add a production probe, change WELA policy recommendations, remove historical mapping candidates or grant Sigma readiness.

Microsoft's [Token Right Adjusted guidance](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-token-right-adjusted) and [advanced audit-policy reference](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration) associate 4703 with token adjustment. The older [4703 event reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4703) names Authorization Policy Change. [WELA's mapping review](audit-catalog-mappings.md) retains both historical candidates as conditional. Native evidence below is specific to the recorded Windows build/UBR, provider manifest, engine and fixed operation.

The opted-in test changes exactly two audit masks and the advanced-audit precedence DWORD on an isolated GitHub-hosted runner. First it sets Token Right Adjusted Events (`0CCE924A-69AE-11D9-BED3-505054503030`) to Success and Authorization Policy Change (`0CCE9231-69AE-11D9-BED3-505054503030`) to None. Then it reverses those two masks. The other 57 audit masks remain at their observed original values. This comparison establishes the selected two-mask behavior under that retained context; it is not an experiment with all other audit sources disabled.

Each phase starts a fresh owned child. A test-only native helper requires an already-enabled `SeDebugPrivilege` in that child's primary token, disables it, reads the complete privilege inventory, restores its original attributes and verifies the complete inventory again. It refuses impersonation, missing or disabled privileges. It never grants a new right, removes a privilege, opens another process, performs a debug operation or changes an account's assigned rights. The executable path is read through `QueryFullProcessImageName` before the operation so `Get-Process` cannot introduce an extra privilege adjustment inside the measured operation.

Acceptance requires two distinct actual Security 4703 records in the TokenRight-only phase: exactly the fixed disable and restoration. The inverse phase must have no matching records during its bounded observation. A match requires the installed provider GUID/name, eventID/version/task, Security channel, success keyword, observed computer identity, fresh record boundary, owned PID/executable, subject and target SID/logon ID, and exact privilege direction/sentinel. The precise UTC envelope starts before the native adjustment and ends after native final inventory equality. Individual syscall-return times are also retained. Security logging can timestamp a record just after the adjustment call returns; the measured verification interval is part of the operation, with no artificial delay or padded interval accepted as evidence. A wider query only collects diagnostic candidates; the strict matcher determines attribution.

The child has a 90-second limit, bounded asynchronous output, a bounded drain and confirmed termination before fixture cleanup. Native event reads have a timeout and require one successful Security-channel status. Query errors, schema differences, extra attributable records, caps, missing events, policy drift or failed cleanup fail the fixture; they are never reported as an empty successful observation. Native events and diagnostic XML remain in the short-lived CI artifacts.

Retained evidence includes actual host/build/UBR, native audit name/GUID listing, all 59 original/prepared/restored masks, typed precedence state, full Security-channel configuration, service states, parent/child tokens and complete privilege arrays, precise timestamps, raw event XML, mapping review, source fingerprints and artifact hashes. Cleanup independently restores both selected masks and the original precedence value or absence, then checks all masks, full channel configuration, service states and parent token. It does not erase generated events or recreate a historical event-log contents snapshot; dispose of the runner.

Run only on the explicitly supported disposable hosted fixture:

```powershell
./tests/TokenRightAttribution.Tests.ps1
./tests/AuditCatalogMappings.Tests.ps1
./tests/TokenRightAttribution.Windows.Tests.ps1 -AllowDisposableAuditWrite
```

This is a build-specific regression for issue #380, not universal proof about Windows 11, domain controllers, AD CS, every privilege, failure auditing, remote forwarding, policy persistence or Sigma Boolean/field requirements. All functionality is built into Windows; Sysmon is excluded.
