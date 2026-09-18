# Command Usage
## audit-settings
The `audit-settings` command checks the Windows event log audit policy settings and compares them with the recommended settings from [Yamato Security](https://github.com/Yamato-Security/EnableWindowsLogSettings), [Microsoft(Sever/Client)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations), and [Australian Signals Directorate (ASD)](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-monitoring/windows-event-logging-and-forwarding).
`RuleCount` indicates the number of [Sigma rules](https://github.com/SigmaHQ/sigma) that can detect events within that category.

### `audit-settings` command examples
Check with the default Yamato Security's recommended settings and save results to CSV:  
```
./WELA.ps1 audit-settings -Baseline YamatoSecurity
```

Check with the Australian Signals Directorate's recommended settings and save results to CSV:  
```
./WELA.ps1 audit-settings -Baseline ASD
```

Check with Microsoft's recommended Server OS settings and display results in a GUI:  
```
./WELA.ps1 audit-settings -Baseline Microsoft_Server -OutType gui
```

Check with Microsoft's recommended Client OS settings and display results in table format:  
```
./WELA.ps1 audit-settings -Baseline Microsoft_Client -OutType table
```

## audit-filesize and configure-eventlogs

`audit-filesize` reads live event-log sizes and retention modes using the same
profile as configuration, preserving exact byte counts in its CSV output.
Use `eventlog-profiles` to list the separate `-LogProfile` choices. The existing
`-Profile` option selects advanced audit policy only.

```powershell
./WELA.ps1 audit-filesize -LogProfile wela-source-2.2.0
./WELA.ps1 configure-eventlogs -LogProfile asd-source-2021-10 -DryRun
./WELA.ps1 configure-eventlogs -LogProfile asd-collector-archive-2021-10 -ApplyLogMode
```

`configure-eventlogs` preserves larger buffers and current modes by default.
`-ResizeLogs` explicitly permits shrinking; `-ApplyLogMode` explicitly applies
source circular or collector archive behavior. Retention days remain unknown
until event volume and archive retention are measured. See the
[event-log profiles and recovery guide](https://github.com/Yamato-Security/WELA/blob/dev/docs/eventlog-settings.md).

## configure
The `configure` command sets the recommended Windows event log audit policy and file size.

Domain NTLM auditing (`AuditNTLMInDomain`) is set to `7` (**Enable all**) only on
confirmed domain controllers. Windows clients, member/standalone servers and
non-DC AD CS servers report **Not applicable** and retain any existing value.
An unavailable or unknown computer role is reported as **Unknown** and skipped.
Role detection uses `Win32_OperatingSystem.ProductType=2`, not the presence of
AD DS tools or a registry key. Before a change, WELA reports the previous numeric
value; legacy value `2` is not described as full auditing. Changes respect the
usual confirmation prompt or `-Auto` and are verified by a registry read-back.
`audit-settings` includes role applicability and the current value in its console
and CSV output. Incoming and outgoing NTLM controls are separate from this policy.

The [Microsoft NTLM auditing guidance](https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection#configure-ntlm-auditing)
describes the policy and event collection prerequisites. A registry read-back
does not prove that events were generated, and GPO or MDM may overwrite a local
change. Validate benign domain NTLM activity and expected Operational events on
an isolated DC before deployment. `tests/DomainNtlm.Tests.ps1` uses mocked OS and
registry access; the associated Windows workflow runs Windows PowerShell 5.1 and
PowerShell 7 without changing host policy.

Live-DC validation for [issue #363](https://github.com/Yamato-Security/WELA/issues/363)
remains pending. Before closing that issue, record the Windows build and confirmed
DC role, the previous registry value/type, the verified `AuditNTLMInDomain=7`
DWORD, and representative NTLM event XML from benign test authentication. Also
check that a second run is idempotent and that clients, member servers and non-DC CAs leave
this domain-only setting unchanged. Mocked policy tests and console/CSV regression
tests do not provide this event-generation evidence.

#### `configure` command examples
Apply Yamato Security's recommended settings (with confirmation prompt before changing settings):
```
./WELA.ps1 configure -Baseline YamatoSecurity
```

Apply Australian Signals Directorate's recommended settings without confirmation prompt:
```
./WELA.ps1 configure -Baseline ASD -auto
```

## update-rules
#### `update-rules` command examples
Update WELA's Sigma rules config files:  
```
./WELA.ps1 update-rules
```

### Outgoing NTLM auditing and restrictions

`configure` defaults to audit-only outgoing NTLM (`RestrictSendingNTLMTraffic=1`).
An existing `Deny all` value (`2`) is preserved, including with `-Auto`. Unknown
values and unreadable policy are also preserved for review.

```powershell
# Audit outgoing NTLM, preserving an existing restriction.
./WELA.ps1 configure -Auto
# Explicitly replace an existing restriction with audit-only mode.
./WELA.ps1 configure -OutgoingNtlmMode Audit -Auto
# Explicitly opt into denying outgoing NTLM (can break authentication).
./WELA.ps1 configure -OutgoingNtlmMode Deny
```

`-OutgoingNtlmMode PreserveOrAudit` is the default. `Audit` and `Deny` are explicit
operator choices; omitting `-Auto` asks before changing the policy. This option
only affects outgoing NTLM. Incoming and domain auditing remain separate controls.
`audit-settings` includes the current outgoing NTLM value and distinguishes audit
from enforcement in its console and CSV results. Policy provenance is reported as
last-applied RSoP GPO data when available, otherwise **Unknown**. RSoP can be stale,
and neither it nor a registry read proves which component last wrote a value.
After a change WELA verifies the registry value; GPO or MDM can subsequently
reapply another value. Validate benign NTLM events in
`Microsoft-Windows-NTLM/Operational` on an isolated Windows host before deployment.

See [Microsoft's outgoing NTLM policy documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-outgoing-ntlm-traffic-to-remote-servers).
The safe mocked regression script is `tests/OutgoingNtlm.Tests.ps1`; its Windows
workflow runs both Windows PowerShell 5.1 and PowerShell 7.
