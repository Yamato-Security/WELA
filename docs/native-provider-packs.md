# Native provider packs

`provider-packs` is a separate, explicit source-configuration workflow. Normal `configure`, audit profiles, WinRM/RDP service settings and rule eligibility remain unchanged. Sysmon and external telemetry are excluded. No pack grants Ready status to a rule.

```powershell
./WELA.ps1 provider-packs -ProviderAction List
./WELA.ps1 provider-packs -ProviderAction Plan -ProviderPack dns-client,capi2 -ResultsPath plan.json
./WELA.ps1 provider-packs -ProviderAction Configure -ProviderPack dns-client -DryRun
./WELA.ps1 provider-packs -ProviderAction Configure -ProviderPack dns-client -Auto -BackupPath C:\WELA-Recovery\dns-run-1 -ResultsPath result.json
```

List reads the bundled definitions; Audit and Plan read actual local Windows metadata. Configure requires Administrator privileges, a nonempty explicit selection and a new recovery directory. Unknown pack names, duplicates, wildcard selection, role overrides and provider options on other commands are rejected. `-DryRun` is supported only for Configure. The PowerShell array examples above are intended for a PowerShell prompt; external `powershell.exe -File` argument parsing may need a wrapper script for multiple values.

| Pack | Exact target provider / channel | Events reviewed | Behavior |
| --- | --- | --- | --- |
| `dns-client` | `Microsoft-Windows-DNS-Client` / `Microsoft-Windows-DNS-Client/Operational` | 3008; requires string `QueryName` | Explicit enable and 32 MiB floor if live schema matches. |
| `dns-server-audit` | `Microsoft-Windows-DNSServer` / `Microsoft-Windows-DNSServer/Audit` | 515, 516, 519 | Server with installed DNS service only; explicit enable and 32 MiB floor. No candidate in the pinned corpus, so no rule credit. |
| `dns-server-analytical` | `Microsoft-Windows-DNSServer` / `Microsoft-Windows-DNSServer/Analytical` | 257, 260, 261; string `QNAME` | Inventory/manual only; never enables Analytical logging. |
| `dns-server-classic` | `Microsoft-Windows-DNS-Server-Service` / `DNS Server` | 150, 770, 771, 6004 | Inventory/manual only; never changes classic DNS logging or debug flags. |
| `capi2` | `Microsoft-Windows-CAPI2` / `Microsoft-Windows-CAPI2/Operational` | 70 | Reuses the existing Appendix C enable/size control exactly. |
| `winrm` | `Microsoft-Windows-WinRM` / `Microsoft-Windows-WinRM/Operational` | 6 | Explicit channel enable/32 MiB floor only; no listener, authentication, service or firewall changes. |
| `rdp-client` | `Microsoft-Windows-TerminalServices-ClientActiveXCore` / `Microsoft-Windows-TerminalServices-RDPClient/Operational` | 1024, 1102 | Explicit channel enable/32 MiB floor only; no RDP server enablement or connection attempts. |

Provider and channel names are checked independently against the local registration and provider-to-channel links. Display names and rule aliases are not substituted. Missing or inaccessible registrations remain unknown/unavailable. DNS Server Audit, classic DNS errors, Analytical query traffic and client lookups are different sources; enabling one does not satisfy the others.

The 32 MiB floors are WELA opt-in choices, **not Microsoft baseline requirements**. CAPI2 retains Microsoft's exact example of 102432768 bytes, rounded upward to Windows' supported 64 KiB increment by the existing writer. Larger buffers, retention modes and every existing descriptor are preserved. Reader permissions are only observed: use the existing `channel-settings -GrantEventLogReaders` workflow to review a CAPI2 read grant separately. Structural permissions do not establish effective access for the forwarding identity.

## Build and schema gates

The reviewed OS families are Windows 11 builds 22000, 22621, 22631, 26100, 26200 and 28000, and Windows Server builds 14393, 17763, 20348 and 26100. This identifies families, not their servicing status or a claim that every patch has an identical event schema. Unknown builds/roles are refused for configuration. Actual DNS service registration is required for DNS Server packs; a domain-controller role alone is insufficient. Combined DC/CA hosts follow the existing host-context reader's refusal policy.

On every assessed host WELA reads the exact provider's event ID, version, channel link, template SHA256 and named field/type definitions. Required DNS query-name fields must be native string fields for every returned version of the expected event. Only observed Administrative/Operational channels are eligible for automatic configuration; an unexpected Debug/Analytical type is refused even if the catalog name appears familiar. Empty/unsupported manifests, missing event IDs and unknown schemas cannot be replaced by static claims. The manifest records field definitions, not actual emitted values or a successful operation.

The provider/role/service/schema fingerprint is rechecked before the shared runner's read, after approval immediately before writing, on readback and in final verification. Channel state itself also retains the shared fresh-snapshot guards. Detected changes or unreadable state fail the control. These checks observe current state; they cannot make native writes atomic against later GPO or another administrator.

## Pinned full rule review and DNS mismatch

The catalog pins the exact bundled corpus SHA256 and fifteen complete native Hayabusa/Sigma definitions from commit `10d1b6dc3ec884daf04d736a7fc78bf2ee898664` of [Yamato-Security/hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules/tree/10d1b6dc3ec884daf04d736a7fc78bf2ee898664). Their original YAML, authors, references and Detection Rule License are retained under `config/provider_rule_sources`; each file has a checked SHA256 and original path in `config/native_provider_packs.json`. YAML is never executed or parsed at runtime. The reviewed fields/operators/conditions are a source inventory, not a complete detection backend.

All six DNS Client definitions themselves require `Microsoft-Windows-DNS Client Events/Operational`; Microsoft's WEF query names `Microsoft-Windows-DNS-Client/Operational`. WELA reports this as `ChannelMismatch`, preserving the full original definitions. It never edits the rule, silently rewrites the channel or credits the six candidates merely because the real channel is enabled. The three DNS Server Analytical rules also retain their original channel strings for comparison against actual registration. The two classic DNS rules remain separate.

Successful channel configuration says nothing about benign operation generation, nonempty event fields, collector arrival, normalized field aliases, modifier/list/Boolean semantics or backend translation. All fifteen candidates stay Conditional, and generic categories remain subject to the existing conservative `rule-eligibility` adapter boundary. Before claiming usability, retain native XML from a benign isolated-host operation, exact build/patch and before/after state, the reviewed channel/field mapping, collector evidence, the actual translated query and matching results. Do not query the suspicious domains in the rule definitions as a test; use a separately reviewed harmless fixture and document the difference.

## Results, recovery and validation limits

`ControlsPlan` is explicitly the pre-write plan, including full-rule review and manifest observations. Configure `Results` contains the shared runner's verified after-state and final result. A selected manual/unavailable pack produces a failed control/nonzero overall exit while independent selected packs may proceed; no partial application is hidden. Dry-run and declined controls are skipped, not applied. `ReadyRules` remains zero and `UnverifiedEvidence` lists the remaining event/backend/access work.

Every attempted native write first records the original enabled flag, exact buffer size, retention and complete descriptor in `before.jsonl`. Restore only the recorded selected channel values using an elevated `wevtutil sl` after reviewing concurrent GPO/administrator changes; do not replace an entire descriptor with an example. No automatic rollback overwrites later changes. Event loss/volume and long-term storage requirements require a measured deployment plan.

The mocked regression suite exercises missing fields/providers, unsupported types/builds, role/service gates, journal-before-write, dry-run, decline, idempotence, preserved ACL/retention/larger buffers, native failure/false success, prompt races and final schema drift. Windows Server 2022/2025 CI on PowerShell 5.1/7 reads real provider manifests and the public CLI plan and checks that channel settings stay unchanged. It creates no DNS queries, log entries, services or subscriptions. Windows 11/DC/CA event-generation and actual backend/collector validation remain pending acceptance work for issue #386.

Primary references: [Microsoft WEF Appendix C/F](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection), [DNS logging and diagnostics](https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-logging-and-diagnostics), [EventMetadata](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventmetadata?view=windowsdesktop-10.0), [EventLogLink](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventloglink?view=windowsdesktop-10.0), [Windows 11 release families](https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information), and [Windows Server release families](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info). The WEF sample identifies event/channel candidates; it does not validate these rule definitions or this implementation on every build.
