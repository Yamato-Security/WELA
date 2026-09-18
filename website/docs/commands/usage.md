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

## audit-filesize
The `audit-filesize` command checks the Windows event logs' file size and compares them with the recommended settings from Yamato Security's recommendations.

### `audit-filesize` command examples
Check the Windows event log file size with Yamato Security's recommendations and save results to CSV:  
```
./WELA.ps1 audit-filesize -Baseline YamatoSecurity
```

## configure
The `configure` command sets the recommended Windows event log audit policy and file size.

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
