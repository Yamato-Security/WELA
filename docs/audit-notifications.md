# OneSettings auditing and Security log warnings

`audit-notifications` is a separate, read-only-by-default command for two native
Windows controls. It does not change normal `configure` behavior or add Sigma
eligibility. Sysmon is out of scope.

```powershell
./WELA.ps1 audit-notifications -ResultsPath notifications.json
./WELA.ps1 audit-notifications -NotificationAction Plan -NotificationControl OneSettings,SecurityWarning -EnablePrivacyChannel
./WELA.ps1 audit-notifications -NotificationAction Configure -NotificationControl OneSettings,SecurityWarning -EnablePrivacyChannel -WarningPercent 90 -DryRun
./WELA.ps1 audit-notifications -NotificationAction Configure -NotificationControl SecurityWarning -WarningPercent 80 -Auto -BackupPath C:\Evidence\warnings-before -ResultsPath C:\Evidence\warnings.json
```

Configure requires Administrator, 64-bit PowerShell and explicit control selection.
Audit and Plan do not modify settings. Options used with another command fail
before dispatch. `-WarningPercent` is a maximum (1–90); an existing positive DWORD
at or below that maximum is preserved. An absent/zero/higher threshold is set to
the selected maximum. An unexpected registry type is preserved and fails the
configuration. Missing values remain missing in the recovery evidence, rather
than being conflated with documented defaults.

| Control | Registry policy | Reviewed source |
|---|---|---|
| OneSettings | `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\EnableOneSettingsAuditing`, DWORD 1 | CIS Windows 11 Enterprise and Windows Server 2022 v4.0.0, 18.10.16.5; Microsoft System CSP |
| SecurityWarning | `HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security\WarningLevel`, DWORD 1–90 | CIS Windows 11 Enterprise v4.0.0 18.5.13 / Server 2022 v4.0.0 18.5.12; Microsoft Windows guest baseline |

Microsoft documents OneSettings for Windows 11 21H2 onward. WELA reviews client
builds 22000/22621/22631/26100/26200 and Server 2022 build 20348 (the latter is an
explicit CIS recommendation, not an inference from client CSP support). It also
requires the exact local `DataCollection.admx` machine policy/key/DWORD mapping
and readable `Microsoft-Windows-Privacy-Auditing/Operational` metadata. The ADMX
hash is retained. Server 2025 OneSettings remains Unknown pending reviewed
support evidence. Unknown builds, policy values other than 0/1, missing templates,
or missing/unreadable channels block OneSettings changes. Merely installing an
ADMX is not enough to pass the host/source gate.

SecurityWarning supports the listed Windows 11 builds and Server 2022/2025
(20348/26100), including DC and CA hosts. The actual OS product type and domain
role must agree. This is the same longstanding Eventlog registry control; Server
2025 support does not imply a CIS Server 2025 recommendation was reviewed.

`-EnablePrivacyChannel` separately authorizes enabling the Privacy Operational
channel after OneSettings policy succeeds. It rechecks producer prerequisites at the shared channel read/write/final-check
boundaries and uses shared channel journaling, stale-state checks and readback, retaining the ACL, log mode and existing size
(the shared technical minimum is 64 KiB, not a CIS sizing recommendation). Without
this switch, a disabled channel is reported and preserved. No diagnostic-data
level, OneSettings download/network policy, service state or forwarding setting
is changed.

Security channel metadata and warning usefulness are separate from registry
compliance. Circular overwrite suppresses this warning; Retain is only a
conditional prerequisite. AutoBackup behavior and unreadable modes are Unknown.
This command never changes retention, fills/clears a log, changes
CrashOnAuditFail, or claims disk-space, archival or forwarding health.

Every mutation uses the shared typed pre-change journal, fresh-state guards,
readback and final drift verification. Recover only the recorded named values
(and channel state if requested) using the [recovery procedure](configuration-results.md).
A partial failure is reported; successful earlier changes are not automatically
rolled back over another administrator's work. Domain GPO/MDM may subsequently
override local policy. Registry verification is not proof of effective producer
behavior or policy persistence.

## Validation and remaining evidence

Fixture tests cover absent/typed values, threshold preservation, role/source and
ADMX/channel gates, stale plans, races, failed/ignored writes, final drift,
idempotence, dry-run and command dispatch. Windows Server 2022/2025 CI observes
native registry/CIM/channel state without changing policy, under PowerShell 5.1
and 7. This is not a Windows 11, DC or AD CS event-generation test.

Before closing issue #378, retain isolated Windows 11 and Server 2022 evidence of
an authorized benign OneSettings attempt with exact build/patch, policy, channel,
native event XML and collection result. Do not assume an EventID without inspecting
the provider on that build. Test warning behavior using disposable Security logs
under explicitly controlled retention/CrashOnAuditFail conditions; never exhaust
a production Security log. Record GPO refresh behavior and verify the intended
reader/collector. Neither registry DWORD grants usable-rule credit.

Sources: [Microsoft System CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-system#enableonesettingsauditing),
[Microsoft Windows guest baseline](https://learn.microsoft.com/en-us/azure/governance/policy/samples/guest-configuration-baseline-windows),
[CIS Windows benchmarks](https://www.cisecurity.org/benchmark/microsoft_windows_desktop).
Reviewed CIS documents are v4.0.0 (client 18.10.16.5/18.5.13; Server 18.10.16.5/18.5.12).
