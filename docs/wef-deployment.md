# Native WEF source configuration and collector subscriptions

For a missing collector listener, use the separately reviewed [`wec-listener` Plan/Apply](wec-listener.md) to create one assigned-IPv4 HTTP5985 listener. It refuses existing listeners and preserves WinRM authentication, services and firewall settings. Collector configuration still requires its own validated prerequisites; listener creation does not prove source arrival.

`wef-source` and `wec-collector` are separate, opt-in commands for a bounded domain/Kerberos topology: source-initiated subscriptions over HTTP 5985 to a dedicated domain member Windows Server collector. They require an operator JSON file with the actual collector FQDN/URI, explicitly permitted source computer/group SIDs, and selected native subscription XML files. Sysmon and EMET are excluded. Local channel enablement or successful configuration does not establish forwarding or add usable Sigma-rule credit.

This implements source configuration and collector subscription creation, not every WEF topology or all acceptance evidence for issue #368. HTTPS/certificate enrollment, workgroups/cross-domain trust, collector-initiated/custom-delivery subscriptions, listener/firewall creation, remote GPO management, updating/deleting existing subscriptions and automatic rollback are outside this command's initial scope. Dedicated workload isolation, network logon rights, capacity and actual event collection remain operator responsibilities.

## Review a plan, then configure

Copy the files under [`config/wef-examples`](../config/wef-examples) into an operator-owned directory. Replace the example FQDN, domain SID and documentation addresses with real values. Select each XML file explicitly; there is no implicit import of a downloaded subscription directory. The same selected definitions and source SIDs belong in both role configs. `SourceSids` controls collector authorization; it does not add computers to a domain group or assert that the current source belongs to a selected group.

```powershell
./WELA.ps1 wef-source -WefAction Plan -WefConfigPath C:\WEF\source.json -ResultsPath C:\WEF\source-plan.json
./WELA.ps1 wec-collector -WefAction Plan -WefConfigPath C:\WEF\collector.json -ResultsPath C:\WEF\collector-plan.json

# On the corresponding source / collector, from an elevated local session:
./WELA.ps1 wef-source -WefAction Configure -WefConfigPath C:\WEF\source.json -DryRun
./WELA.ps1 wec-collector -WefAction Configure -WefConfigPath C:\WEF\collector.json -DryRun
./WELA.ps1 wef-source -WefAction Configure -WefConfigPath C:\WEF\source.json -Auto -BackupPath C:\WEF\source-before-01 -ResultsPath C:\WEF\source-result.json
./WELA.ps1 wec-collector -WefAction Configure -WefConfigPath C:\WEF\collector.json -Auto -BackupPath C:\WEF\collector-before-01 -ResultsPath C:\WEF\collector-result.json
```

The default action is `Audit`. `Audit` and `Plan` only read. A stopped WinRM service is reported as an unmet prerequisite; these actions do not enter the WSMan provider in a way that might start it. `Configure -DryRun` creates no backup directory and makes no changes. It reports currently unmet prerequisites rather than pretending proposed service/hardening changes already took effect. Configuration without `-Auto` asks for each change. Declines and partial failures remain visible. Use a new backup directory for every real run.

## Source controls

| JSON setting | Behavior |
|---|---|
| `CollectorFqdn`, `CollectorUri` | Matching DNS identity and `http://FQDN:5985/wsman/SubscriptionManager/WEC`; IP identities, credentials, fragments and alternate endpoints are rejected. |
| `SubscriptionManagerSlot`, `RefreshSeconds` | One explicit numeric REG_SZ value under the machine SubscriptionManager policy list, with a refresh interval of 10–86400 seconds. WELA validates the local `EventForwarding.admx` mapping. Other values are preserved; an occupied different slot is refused. |
| `GrantNetworkServiceRead` | Explicit boolean. On a confirmed domain member workstation/server, `true` permits adding NETWORK SERVICE (`S-1-5-20`) to Event Log Readers (`S-1-5-32-573`). Existing members are preserved and journaled. `false` only assesses membership. |
| `ApplyChannelProfile` | Explicit boolean. `true` reuses the shared Microsoft WEF Appendix C channel controls, including their exact byte sizes, larger-buffer preservation and readback. |
| `GrantCapi2Read` | Separate explicit boolean; requires `ApplyChannelProfile`. Allows only the shared CAPI2 Event Log Readers read-ACE operation, with the existing descriptor-preservation checks. See [channel settings](native-channel-access.md). |
| `Hardening` | `AssessOnly` reads the ASD Digest prerequisite; `ApplyASD` allows setting `WSMan:\localhost\Client\Auth\Digest` to `false`. |

WinRM is set to Automatic and started when necessary, without creating a source listener. Configuring SubscriptionManager is blocked until the observed local source prerequisites match: domain membership, supported ADMX mapping, running Automatic WinRM, disabled Digest, enabled Kerberos, observed NETWORK SERVICE membership and enabled selected channels. These are configuration checks only; provider auditing/SACLs, token refresh, effective read access and actual events are separate.

On a domain controller, BUILTIN group membership has domain/AD authority rather than endpoint-local authority. WELA does **not** add the forwarding identity through this local group workflow. Have the domain administrator establish and verify appropriate membership/access separately; an existing membership may be observed if the local read API supports it, otherwise it is reported as unknown. There is no fallback that changes replicated AD membership. Windows 11, member-server, DC and AD CS sources each still need their applicable audit policy and representative event evidence.

## Collector controls and prerequisites

The local host must be a domain member server whose observed DNS name equals `CollectorFqdn`. WinRM and Wecsvc can be set to Automatic and started. WELA never runs `winrm quickconfig`, `wecutil qc` or `Enable-PSRemoting`, and never creates or broadens listeners/firewall rules.

Before enabling ForwardedEvents or creating a subscription, WELA requires one existing listener matching `ListenerAddress`, HTTP, enabled state, port 5985 and URL prefix `wsman`; one named effective ActiveStore ingress rule matching inbound Allow, Domain profile, TCP 5985 and the exact `IngressLocalAddresses`/`IngressRemoteAddresses`; running Automatic services; enabled collector Kerberos; and the two assessed ASD hardening settings below. Supply explicit IP/CIDR address lists, not `Any` or `/0`. The check verifies the selected definitions, not actual packet acceptance, reachability, profile activation or the absence of other broad rules. Listener/rule evidence is retained in JSON. Explicit address scopes are compared by IP/network identity, recognizing native IPv4 dotted-netmask spelling and equivalent IPv6 compression while preserving network size, address family and scope ID. Raw native strings remain visible; dynamic aliases, malformed masks and different scopes never become an ingress match.

`Hardening: "ApplyASD"` explicitly permits setting `WSMan:\localhost\Service\Auth\CbtHardeningLevel` to `Strict` and `WSMan:\localhost\Shell\AllowRemoteShellAccess` to `false`. Disabling remote shells prevents new remote-shell sessions; review this on a dedicated collector using local/out-of-band administration. `AssessOnly` records unmet hardening and blocks subscription creation. Policy-owned mismatches are refused; WELA does not rewrite their controlling GPO. No Basic, CredSSP, TrustedHosts, authentication fallback or firewall access setting is changed.

ForwardedEvents enablement preserves its size, retention mode and security descriptor. Size/retention planning is a separate [`configure-eventlogs`](eventlog-settings.md) operation. Existing subscriptions with matching selected fields are left unchanged; a different or unreadable existing subscription is refused. New selected subscriptions are created with `wecutil cs` using a locked UTF-8 XML file stored in the recovery directory. Every native exit code is checked, the definition is read back and checked again at completion, and prerequisites are reread before each create and at the final check.

## Subscription XML and evidence

The supported input is the native Subscription namespace, SourceInitiated type, native EventLog URI, HTTP transport, ForwardedEvents destination and Normal/MinLatency/MinBandwidth delivery preset. Enabled, ReadExistingEvents, content format and locale must be explicit. QueryList uses unique numeric Query IDs, exact native channel paths and nonempty Select/Suppress XPath expressions. Wildcard/provider channel names, external-provider channels, Sysmon/EMET, DTDs, unknown settings and custom delivery are rejected. This checks supported structure, not Windows XPath execution; native `cs` remains the final syntax validator.

An empty `AllowedSourceDomainComputers` input is filled from the explicit `SourceSids`; a nonempty value must match that authorization exactly. No empty authorization reaches `wecutil`, avoiding Windows' broader default authorization. Non-domain/certificate authorization is not supported. The example Security 4740 filter is illustrative and is not a complete baseline or a recommendation to lock an account for testing.

Readback equality covers ID, enabled state, selected delivery preset, ReadExistingEvents, content format, locale, description, destination, explicit source authorization and normalized QueryList structure/text. It is not full byte equality. Native-generated Delivery/EventSources and default transport/credential fields may be returned by `gs`; delivery/runtime expansion is not counted as an operator configuration difference when a supported preset is selected. Unknown observed fields or unrecognized authorization representations fail closed rather than receiving a matching claim. Requested and observed definitions/enabled flags are separate: an observed disabled subscription remains `ObservedEnabled: false`, even if the operator input requests enablement. Source-only runs leave the collector's observed state unknown.

JSON retains exact filters, disabled flags, local channel enablement/mode/ACL, local configuration results, native `wecutil gr` output and its errors, and unverified prerequisites. A separate [`TypedRuntime`](wec-runtime.md) object adds native activity/error/time fields and bounded per-source observations; its Unknown/Partial status stays independent of local configuration success. On collectors, local channel metadata is explicitly labeled **collector only**; it does not describe remote source states. Localized runtime text is preserved as evidence without inferring connected-source counts or arrival success. `LocalConfigurationStatus: RequestedSettingsMatch` describes the selected local settings only. A non-dry-run with unmet prerequisites, failed writes or mismatched final settings exits nonzero and is incomplete.

## Recovery and lab acceptance

`before.jsonl` is written before each mutation. Review its exact Target/Before/Desired and the results before recovery. For a newly created subscription, it records absence and stores the prepared XML; remove that exact ID only after verifying its current definition still belongs to this run. Existing subscriptions are never edited. For the new SubscriptionManager value, compare the current value with Desired before removing only that value; keep other list entries and parent keys. Restore WSMan values and service start/running states only after verifying their present state and current policy authority. Remove only the newly added group SID after comparing the full membership snapshot; DC membership is never changed by this workflow. For channel restoration, use the channel journal and descriptor-preservation guidance. Recovery is deliberately manual so a newer operator/GPO change is not overwritten.

Safe fixture tests exercise the public command/report, journals, readback failures, occupied slots, explicit authorization, native create failures, configuration drift, DC group protection and blocked prerequisites. Windows PowerShell 5.1/PowerShell 7 CI adds real **read-only** channel, service, WSMan, firewall and ADMX assessment. These tests do not deploy subscriptions or prove forwarding.

Before closing issue #368, an isolated domain lab must configure a dedicated collector and Windows 11/member-server/DC/AD CS sources, verify source identity/token read access (including any required token/service refresh), preserve runtime status, and demonstrate native events matching each selected query arriving with the expected source identity/timestamps. Include disabled-query, denied-source, absent-channel, GPO refresh, idempotence, drift and recovery cases. Use a deliberately chosen benign native Application/System event or a controlled test account/object relevant to the query; record actual events, not merely a successful command or ACE. Forwarded Sigma coverage remains unassessed until those events and the processing pipeline are validated.

## Sources

- [Microsoft: WEF and source prerequisites, including Appendix C](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection).
- [Microsoft: source-initiated subscription setup and validation](https://learn.microsoft.com/en-us/windows/win32/wec/setting-up-a-source-initiated-subscription).
- [Microsoft: wecutil command semantics](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wecutil).
- [Microsoft: WinRM settings and authentication](https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management), [remote authentication](https://learn.microsoft.com/en-us/windows/win32/winrm/authentication-for-remote-connections).
- [Microsoft: RemoteManagement policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-remotemanagement), [RemoteShell policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-remoteshell).
- [ASD: Windows event logging and forwarding](https://www.cyber.gov.au/business-government/detecting-responding-to-threats/event-logging/windows-event-logging-and-forwarding), assessed for the source Digest, collector CBT/remote-shell, service, access and scoped-ingress requirements. This command does not claim complete ASD collector compliance.
