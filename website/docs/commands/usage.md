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
