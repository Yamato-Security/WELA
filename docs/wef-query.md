# Native source QueryList preflight

`wef-query` executes the exact QueryList from one explicitly selected subscription in an existing WEF **Source** config against local Windows logs. It checks actual native query behavior and the current caller's read access, preserving matching event XML in a new private evidence directory. It changes no Windows settings, contacts no collector and creates no subscription or event.

```powershell
./WELA.ps1 wef-query -WefQueryConfigPath C:\WEF\source.json `
  -WefQuerySubscriptionId 'WELA Native Security Example' `
  -WefQueryOutputPath C:\Evidence\query-001 `
  -WefQueryMaximumEvents 16
```

Use native 64-bit Windows PowerShell 5.1 or PowerShell 7 under the intended reader's session. The observed host must be within WELA's reviewed Windows 11 / Server 2022/2025 build scope, with EventLog and Winmgmt already running. The command does not start services, elevate, impersonate another user or refresh a token. `-Auto`, `-DryRun`, `-WhatIf`, alternate credentials, remote query options and unrelated configuration arguments are rejected. A source's current domain membership does not authorize a remote operation because this command performs none.

The source JSON and explicitly listed subscriptions use the existing [WEF deployment](wef-deployment.md) schema: collector FQDN/URI, domain-format source SIDs and supported built-in native subscription definitions. Select one exact, case-sensitive subscription ID from that config. The collector identity and requested enabled flag remain recorded operator inputs; neither becomes an observed collector setting or verified identity. An explicitly disabled subscription can still be preflighted against historical local records.

## Exact query and separate error diagnostics

The existing parser validates supported subscription structure, native channel paths, Select/Suppress clauses and excluded external providers. The extracted QueryList text is then passed directly to native `EvtQuery`; WELA does not rewrite XPath, remove suppressions, substitute a fixed query or enable tolerance for matching evidence. The query runs in reverse record order. Every native channel status must be attributable to a selected channel, and every selected channel must have a reported status before a complete result is possible.

If strict query creation fails, its native error remains the primary outcome. A second, separately labeled native diagnostic query can return per-channel status codes with `EvtQueryTolerateQueryErrors`. Windows may recover only part of a malformed XPath under that flag, so **no records from the diagnostic query are read or accepted as matches**. Missing diagnostic details remain unknown. Numeric error codes are preserved without parsing localized message text.

| Status | Meaning |
| --- | --- |
| `MatchesObserved` | Strict query completed, every selected channel status succeeded, and at least one native matching event was retained. |
| `ReadAllowedEmpty` | Strict query completed with successful channel statuses and no matching events. Empty is distinct from denial, missing logs or invalid syntax. |
| `QueryFailed` | Strict query creation failed; inspect its error and the separate diagnostic channel statuses. |
| `Partial` | The strict query opened, but a cap, read failure, channel error or incomplete cleanup prevented completeness. Retained samples remain individual observations. |
| `Unverified` | Input, worker, context, provenance or artifact checks failed. Inspect the diagnostic and available evidence. |

Only the first two statuses return exit 0. A valid query can legitimately return no records, and a broad valid query can exceed the sample limit. A native success establishes behavior for the current local logs and actual caller at observation time; it does not prove that a future event, another account or the forwarding service will have the same result.

## Bounds and evidence

Each original input is limited to 1 MiB, with 4 MiB aggregate decoded text. The selected QueryList is limited to 65,536 UTF-16 characters, 16 distinct channels and 128 filters. `WefQueryMaximumEvents` accepts 1–64 (default 16). One extra native record is requested to distinguish an exact-sized result from a cap; the extra record is not rendered or retained. Native XML is bounded to 1 MiB of UTF-16 per record and 4 MiB of aggregate UTF-8 matching XML.

The fixed worker uses the same installed PowerShell engine and actual caller context. Its native query handles remain on one thread. Each `EvtNext` uses a five-second timeout; the parent bounds the entire worker to 45 seconds, with bounded output draining and termination waits. A timeout or unconfirmed worker termination cannot earn a complete result. Bounded source, native query-status arrays and pipe buffers prevent unconstrained result allocation.

The new output directory grants access to the current user, SYSTEM and local Administrators. Original inputs and parent ACLs are not changed. Paths must be ordinary local paths accepted by WELA's recovery artifact helpers; existing output directories and observed reparse paths are refused. Raw event payloads can contain sensitive operational data, so retain them as evidence under the intended reader's access policy.

Outputs include decoded `source-config.json`, `subscription.xml`, exact `query.xml`, the worker `request.json`, `worker.json`, individual `event-NNN.xml` matches and a final `manifest.json`. The manifest records original file paths/hashes, source fingerprints, query hash, actual host/DNS context, engine hash/version, before/after reader and channel observations, strict/diagnostic query results and artifact hashes. The original byte hashes are distinct from the decoded text artifacts. Unsuccessful runs retain whatever evidence was available; a missing final manifest means the output is incomplete.

The worker's SID, logon, group attributes and privileges must match the caller and remain stable. Host, input bytes, implementation, engine, channel configuration and saved hashes are rechecked before completeness. Returned event channel/record identity and exact observed local computer names must be consistent; no same-label arbitrary DNS suffix is accepted. These checks are observations rather than an atomic channel snapshot, and hashes establish consistency rather than authenticating an evidence author.

`ConfigurationChanges` and `ReadyRuleCredit` remain zero. The result does not establish NETWORK SERVICE's effective token, source group membership, policy/SACL generation prerequisites, subscription delivery, origin of historical records, loss, forwarding latency, retention duration or Sigma readiness. Use [channel-read](channel-read.md) for a simple current-token channel read and [wef-arrival](wef-arrival.md) for the separate exact collector-presence workflow. Issue #368 still requires representative multi-host source/collector validation.

## Native validation

The disposable Server 2022/2025 workflow runs both PowerShell engines through the public command. It selects an independently read real System record, verifies complete XML equality, suppresses that same record to obtain a genuine empty result, exercises malformed XPath and a mixed missing-channel query, and proves the event cap with an extra native record. An owned standard user and temporary CAPI2 deny ACE exercise actual access denial. The fixture independently restores the original channel descriptor and removes its owned account, then compares selected channels, services, all audit masks, precedence and the operator token. These temporary fixture changes are absent from the product. No domain setup, event generation or forwarding is claimed by this native suite.

Microsoft references: [EvtQuery](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtquery), [query flags and partial XPath recovery](https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_query_flags), [per-channel query information](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtgetqueryinfo), [native property types](https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_query_property_id), [EvtNext completeness and timeout](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtnext), and [native event XML rendering](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtrender).
