# Bounded local event-delivery measurement

`event-measurement` observes callbacks from one explicitly selected local Windows event channel for 1–60 seconds. `Plan` is the read-only default. `Run` creates a new private evidence directory; it changes no channel, policy, service, provider, subscription definition or retention setting, and generates no test events.

```powershell
# Read actual channel registration, configuration, log identity and reader context.
./WELA.ps1 event-measurement -MeasurementChannel Security

# Observe ten seconds, with at most 256 retained events, and verify a native EVTX sample.
./WELA.ps1 event-measurement -MeasurementAction Run -MeasurementChannel Security `
    -MeasurementSeconds 10 -MeasurementMaximumEvents 256 `
    -MeasurementOutputPath C:\Evidence\new-security-sample -MeasurementExportEvtx
```

The exact selectable channels are `Security`, `System`, `Application`, `Microsoft-Windows-DNS-Client/Operational`, `Microsoft-Windows-CAPI2/Operational`, `Microsoft-Windows-WinRM/Operational` and `Microsoft-Windows-PowerShell/Operational`. The actual channel must be registered, enabled and Administrative or Operational, and the current native 64-bit Windows reader must have access. Each event computer name must exactly match `MachineName` or local hostname/domain names obtained from native `IPGlobalProperties`; these observed names are recorded in the reader snapshot. A different domain sharing the same short hostname is not accepted. No DNS query is performed. A missing feature, disabled channel, denied read or unavailable identity is **Unverified**, with a nonzero exit; this command does not enable it. Administrative rights alone do not guarantee channel access. Select only a channel whose event contents you are authorized to retain.

`ForwardedEvents` is excluded because collector record IDs and original source XML require a separate validated mapping. Remote sources, arbitrary/wildcard channels, Sysmon and other third-party channels, and Analytic/Debug traces are excluded. System and Application are shared built-in channels: their measurement includes all locally sourced records delivered there, including records from non-Microsoft providers. The original provider identity is retained; selecting a built-in channel does not assert a Microsoft-only producer set. `-DryRun`, hypothetical `-Role`/`-Build`, configuration options and unrelated command options are rejected. Use `Plan` for read-only preflight.

## What is measured

The native observer uses local `EvtSubscribe` with `EvtSubscribeToFutureEvents | EvtSubscribeStrict` and a C# callback. No PowerShell script executes on the native callback thread. Windows serializes delivery behind this callback, so its rendering/bookmark overhead is part of this observer's workload; the result is not an independent benchmark of the producer. Once registration returns, a `Stopwatch` starts the observation window. Callbacks arriving before that window are excluded and counted separately. Each retained event records its monotonic offset at serialized callback processing, original rendered XML and a native bookmark. The interval ends at the requested monotonic deadline; registration and shutdown/serialization are outside the rate denominator. UTC start/completion values aid correlation but do not replace the monotonic clock.

`ObservedDeliveriesPerSecond` is the retained callback count divided by that completed interval. It is **not** a producer-generation rate, event `TimeCreated` density, causal latency, sustained throughput capacity, collector/backend ingestion rate or evidence of losslessness. Events generated before the window can be delivered during it; callbacks queued until after its deadline are outside it. Native subscription diagnostics, consecutive local record IDs, source snapshots and EVTX readback detect some inconsistencies. None proves that every upstream event was generated or delivered: `LossAssessment` remains **Unknown** even for a successful window.

The cap is 1–1024 events, one MiB of UTF-8 XML per event and sixteen MiB per batch. Merely reaching the selected event count is allowed; observing an additional callback within the window produces `EventCapExceeded`. Native errors (including stale/missing-record notifications), XML caps, duplicated/reordered/discontinuous IDs, invalid bookmarks, source/reader drift and observed clear/reset indicators retain available partial evidence and suppress a valid rate. A busy source can exceed these bounds; choose a shorter interval, rather than treating a capped sample as an exact rate.

A zero-delivery completed window is `NoDeliveriesObserved`, exit zero, with a **null rate** and no fabricated EVTX. It establishes only that this observer retained no deliveries in its interval. Other failures are `Unverified`, exit one. A failure before an output directory can be created returns its diagnostic without claiming a durable receipt. A later failure retains the private partial bundle and diagnostic. The manifest lists hashes of saved artifacts; original XML and bookmarks remain separate files.

## EVTX bytes and preservation

`-MeasurementExportEvtx` creates `sample.evtx` using native `EventLogSession.ExportLog`, selecting only the sampled numeric record IDs through a structured query. It reopens the file with the native event reader and requires exactly every original identity and payload, with no missing, extra or duplicate records. Namespace-aware semantic comparison permits localized `RenderingInfo` differences, while preserving System plus EventData/UserData/BinaryEventData, including the order of mixed text and element content. Equivalent namespace prefixes, attribute ordering, adjacent text/CDATA and element-only indentation do not change payload identity; mixed-content and explicitly preserved whitespace remain data. The original XML is never rewritten. Reused IDs after a clear or overwritten/wrapped source records cannot substitute for an observed sample that differs in content.

Verification holds a file read handle denying writes/deletion, streams its SHA-256, checks every recovered record, and observes source/reader state again. The sample and other saved artifacts are rehashed before the final manifest; a changed artifact revokes verified bytes and is recorded as unverified. Only a successful readback exposes `Evtx.Bytes`. These are **logical bytes of this particular native export artifact**, including EVTX format overhead. They are not the XML byte count, physical allocation, live-channel growth, compression efficiency, backend storage or a forecast of 18 months of retention. Export is limited to a 64 MiB artifact; an oversized native output is rejected and retained as unverified, without truncation. Native export and reopen are synchronous APIs; the delivery window is bounded, but subsequent native I/O may take longer.

Output must be a new directory under an existing parent on an ordinary local fixed drive. UNC/device paths, ADS, wildcards, control characters, reparse paths, reserved DOS names and trailing-dot/space aliases are refused. Before evidence files are created, inherited directory access is removed and access is limited to the current reader, SYSTEM and local Administrators. These parties can still change their own evidence; file hashes and fresh checks are integrity observations, not signatures or protection against a concurrent administrator. There is no atomic transaction combining native subscription, export and channel configuration. No source EVTX is cleared, moved, resized or overwritten, and no product rollback is needed. Operators can remove a reviewed output bundle using their normal evidence-retention policy.

This feature is separate from `retention-health`'s retrospective `TimeCreated`/XML sampling and from `evtx-recovery`'s exact single-probe archive verification. It awards no Sigma readiness credit and supplies no translated query or backend proof.

## Validation and remaining labs

Safe fixtures exercise selection and CLI guards, UserData/namespace handling, protected artifacts, exact-record query groups, zero/capped/error windows, bookmark/source/context drift, duplicated or discontinuous IDs and missing/extra/changed EVTX contents. The gated native workflow runs on disposable Server 2022 and 2025 under Windows PowerShell 5.1 and PowerShell 7. It temporarily enables process-creation success plus precedence/command-line capture, starts the public command, generates three fixed uniquely owned `cmd.exe /d /c echo WELA_PROBE_…` processes, verifies actual 4688 deliveries and native EVTX reopening, then verifies restoration of all 59 audit masks and the exact prior registry values/types/absence. It neither clears system logs nor registers arbitrary providers. The fixture is refused outside explicit opt-in on a GitHub-hosted ephemeral runner.

Native CI validates the Security-channel sample on those disposable hosts. Windows 11, DC/ADCS roles, other selectable channels, long intervals, high load, real queue loss, concurrent clears and downstream backends need separate environment-specific validation. Passing CI does not validate an organization's retention duration or every rule that consumes the channel.

## Microsoft API references

- [IPGlobalProperties.HostName](https://learn.microsoft.com/en-us/dotnet/api/system.net.networkinformation.ipglobalproperties.hostname): native local computer-name metadata.
- [EvtSubscribe](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtsubscribe): local future-event subscriptions and supported Admin/Operational channels.
- [Subscription flags](https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_subscribe_flags): strict missing-record notifications and future-only origin.
- [Subscription callback](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nc-winevt-evt_subscribe_callback): service-owned event handles, serialized callback delivery and strict stale notifications.
- [EvtRender](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtrender): original event and bookmark XML.
- [EvtExportLog](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtexportlog): exact filtered exports, structured queries, new target files and header-only empty exports.
