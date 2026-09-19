# Native provider assessment

`audit-settings -Baseline` observes native Windows channels and provider prerequisites instead of assuming that every registered provider is enabled. Sysmon and external telemetry are outside this assessment.

```powershell
./WELA.ps1 audit-settings -Baseline YamatoSecurity -ResultsPath audit.json -HtmlPath audit.html
```

The JSON and self-contained HTML reports preserve channel state, log mode, security descriptor (SDDL), maximum size, registered provider names, metadata read errors, provider observations and source-to-rule mappings. The existing audit CSV includes the same native evidence as a JSON field. Standard output shows channel and provider states; table/grid output includes channel state and generation readiness. No channel, ACL, service or provider policy is modified by these checks. The existing advanced-audit checks and report file writes still run.

`-ResultsPath` and `-HtmlPath` here apply to the ordinary `audit-settings -Baseline` assessment. `audit-settings -Profile` remains an advanced-audit-only view with its existing `-PlanPath` export.

## What the states mean

| Observation | Meaning |
| --- | --- |
| Channel `Enabled` / `Disabled` | Actual `Get-WinEvent -ListLog` `IsEnabled` value. |
| Channel `Not installed` | Windows reports no registration for that exact channel. This does not prove that every part of the associated product is absent. |
| Channel `Unknown` | A read failed, was denied, or did not return the required state. Error category, ID and message are retained. |
| Current setting `Conditional` | At least one channel is enabled, but provider and event-specific generation have not been validated. This is not an enabled-rule claim. |
| Provider `Unknown` | A required provider/status query was unavailable or failed. The channel observation is still retained separately. |
| Domain NTLM `Not applicable` | The host is confirmed not to be a domain controller. An unreadable role remains unknown. |

Each exact channel is read independently. An enabled AppLocker EXE/DLL channel does not hide a disabled MSI/Script channel. PowerShell's `pwsh` metadata alias for classic event 400 maps to `Windows PowerShell`; it does not prove PowerShell 7 logging. Catalog selectors use concrete channel names or metadata aliases. In both filtering and source mapping, rule channels are patterns matched against these concrete names. The Security-Mitigations catalog reads separate KernelMode and UserMode channels, mapping the existing wildcard rules to both without issuing broad wildcard channel queries or mapping a channel-specific rule to its sibling.

## Provider evidence and coverage limits

- AppLocker: Application Identity service state and GP effective rule collection types, modes and rule counts. Microsoft documents that `Get-AppLockerPolicy` cannot see policies deployed through the AppLocker CSP. Empty GP output therefore does not prove the absence of a policy. Shared channels can also contain App Control events. No AppLocker rules are created or modified.
- NTLM: separately observed outgoing and incoming registry values/types, host ProductType, and domain policy only on a DC. Audit modes, restrictions, exception lists and traffic directions are not interchangeable. A DWORD observation alone does not establish which rule events will occur.
- Defender: WinDefend service state, runtime mode, antivirus/real-time/behavior/network inspection flags. Passive mode, ASR, network protection and controlled folder access have different prerequisites. An enabled channel is not proof of active protection or of all Defender events.
- Other native providers: exact channel registration and available service state, including BITS, printing, WMI, Terminal Services, DFSN, Firewall and SMB client. Provider policy, activity and required event fields remain conditional. Application and System channels can receive events from many independent providers.

No rule receives current or ideal usable-rule credit merely because a channel or Security audit policy is enabled. Rules remain in the complete, deduplicated corpus inventory and in `UnusableRules.csv` (meaning **not confirmed usable**, including conditional/unknown sources). `RuleEligibility.csv` and JSON/HTML provide per-rule reasons and explicit native/full-corpus denominators. Configuration estimates remain separate from detection readiness. See [native rule eligibility](native-rule-eligibility.md) for the supported imported-evidence checks and their trust boundary.

Without complete lab evidence, the reported Ready count is zero. This describes missing validation, not the usefulness of logging. The separate `rule-eligibility` command can review supported imported evidence for its recorded context/time; it never silently applies old lab results to the currently audited host. Additional native provider adapters still require reviewed policy, event, field and backend evidence.

## Validation and outstanding integration evidence

The regression suite uses the real catalog and public audit/CSV/JSON/HTML path with injected Windows reads. It exercises disabled, absent and denied channels, unreadable ACL metadata, AppLocker policy and sibling-channel states, NTLM role applicability, Defender passive mode, provider query failures, HTML escaping and stable rule denominators. Windows PowerShell 5.1 and PowerShell 7 CI also run read-only native smoke checks and retain their JSON/HTML artifacts. The release workflow already packages the complete `modules` directory, including `NativeProviders.psm1`.

Keep issue #366 open until isolated Windows 11, member server, DC and AD CS tests provide the requested evidence. On snapshots, record OS/build, WELA commit and effective provider policy; compare enabled and deliberately disabled test channels; capture absent-feature and access-denied reports; generate benign, representative provider events and inspect their XML fields. For forwarding deployments, separately confirm central ingestion. Restore the snapshots afterward. The hosted-runner read-only checks do not replace these event-generation and forwarding tests.

## Microsoft sources

- [Get-WinEvent channel metadata](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.6)
- [Get-AppLockerPolicy effective policy and CSP limitation](https://learn.microsoft.com/en-us/powershell/module/applocker/get-applockerpolicy?view=windowsserver2025-ps)
- [Application Identity service](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/configure-the-application-identity-service)
- [NTLM auditing prerequisites](https://learn.microsoft.com/en-us/defender-for-identity/deploy/event-collection-overview)
- [Incoming NTLM audit policy](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-audit-incoming-ntlm-traffic)
- [Get-MpComputerStatus](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus?view=windowsserver2025-ps)
- [Defender active/passive modes](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility)
- [Exploit protection and other protection event channels](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-windows-events)
- [Windows PowerShell classic event logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_eventlogs?view=powershell-5.1)
