# Native probe presence on a WEF collector

`wef-arrival` reads the **local ForwardedEvents log** and checks whether it contains the exact original Security 4688 event from a completed [native-validation](native-validation.md) probe bundle. It queries Windows and writes a new private evidence directory; it does not configure subscriptions, start services, enable auditing, launch a process, change existing permissions or contact a remote computer.

```powershell
# First collect a real fixed probe on the source using native-validation.
# Transfer that completed, protected bundle through your approved process.
# On the collector, using the actual intended reader's session:
./WELA.ps1 wef-arrival -ArrivalProbePath C:\ReviewedSourceEvidence\probe-001 `
  -ArrivalOutputPath C:\ReviewedCollectorEvidence\arrival-001
```

Use 64-bit Windows PowerShell 5.1 or PowerShell 7. Both paths must be ordinary local filesystem paths on fixed drives. The output's parent must exist, the output directory must be new and outside the source bundle, and observed reparse points are refused. Relative paths follow PowerShell's current location. No automatic elevation, alternate credentials or remote session is used. All unrelated configuration/profile/output options, including `-Auto` and `-DryRun`, are rejected before command dispatch.

## Source evidence validation

The importer accepts the five-file `WelaNativeProbeComponents` / `security-4688-command-line-v1` contract from the existing probe collector: `manifest.json`, `before-state.json`, `after-state.json`, `process.json` and `event.xml`. It checks exact artifact names, SHA-256 fingerprints, strict JSON without duplicate properties, successful native-probe status and equality between embedded metadata and hashed files. Input files are limited to 4 MiB each; unknown or incomplete bundles are rejected before querying the collector or creating output.

It validates all 59 typed audit masks, typed registry prerequisites, actual recorded source role/build/patch/join context, the fixed System32 cmd.exe echo command and unique probe marker, process identities, source timestamp ordering and stable before/after state. The source XML must match the recorded native probe, including provider GUID, successful 4688 version 2, original computer, child/creator PIDs and complete command line. Combined DC/CA and source builds outside the existing probe's reviewed scope are refused. Source evidence is revalidated after a successful query; a changed bundle prevents a presence result.

These checks establish consistency, not authenticity. Hashes and producer status are not signatures, and an evidence author can manufacture a self-consistent bundle. Protect the original source evidence and use an independently reviewed collection/transfer process. Do not use the synthetic test fixtures as real source evidence.

## Collector query and matching

The query uses the physical `ForwardedEvents` channel, the Security-Auditing provider, EventID 4688, the exact source computer and a two-second window centered on the original event's timestamp. This is a search window around the recorded source timestamp, not a clock-skew allowance or measured delivery time. It reads at most 512 candidates; reaching that limit leaves completeness unknown and the result unverified. This is one synchronous native query, not a polling loop or a guaranteed wall-clock timeout. Rerun into a new directory after a later collector observation if needed.

Every original `System` and `EventData` value must match. XML namespace prefixes, attribute order and formatting indentation are insignificant, while original payload text, attributes, record identity and data order remain significant. The optional native `RenderingInfo` section can differ because it contains rendered/localized strings. Other added event sections, duplicate structures, DTDs and processing instructions within the event are refused. Microsoft documents that [forwarding retains original event data and can add information](https://learn.microsoft.com/en-us/windows/win32/wec/windows-event-collector); [RenderingInfo](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-renderinginfo-eventtype-element) contains rendered message strings. This deliberately narrow matcher leaves unsupported serialization unverified rather than guessing.

The reader records its actual SID, account name, authentication/impersonation information and group SIDs. Collector computer/build/patch/domain/installed-role context and ForwardedEvents configuration are read before and after the query. Changes to the host, reader or channel prevent a successful result. Effective read access is demonstrated only for the session that actually performed this query; observed group SIDs are not an access assessment for other users. A disabled channel can still contain historical records: its observed enabled flag is reported separately from presence, and no WEC service/active subscription health is inferred.

## Results and recovery

`PresentOnCollector` and exit 0 require exactly one matching original event, uncapped query results, unchanged collector context and unchanged source evidence. No match, duplicates, malformed candidates, denied reads, caps or drift return `Unverified` and exit 1. Absence does not prove loss; an event could be pending, excluded, expired or outside the currently readable data. Presence can be historical and does not establish when or how the event entered the log.

The output contains `source-event.xml`, `collector-before.json`, `collector-after.json` when readable, and `collector-event.xml` for a single match. For ambiguous matches, at most two raw duplicate XML records are retained without selecting one. `manifest.json` is written last and includes the original source manifest/fingerprint, actual collector observations, exact query and observation times, counts, diagnostics and hashes for emitted components. Candidate events that do not match are not exported. Failed runs preserve available observations and raw evidence; a missing final manifest means output is incomplete. Manifest or file-write failure propagates as a command failure.

The new output directory's DACL grants access only to the current user, SYSTEM and local Administrators. Existing input directories and their ACLs are untouched. Files use CreateNew and verified readback rather than overwriting previous evidence. Treat evidence as sensitive host/process metadata. After an interrupted run, inspect the owned output directory and retain or remove it through your normal evidence process; no Windows policy recovery is needed. Filesystem checks are observations, not a lock against later concurrent changes, so protect and reverify evidence before sharing it.

The result always retains `SubscriptionAttribution: Not established`, `TransmissionLatency: Not measured`, `ClockSynchronization: Not established`, `ReadyRuleCredit: 0` and `PolicyChanges: 0`. Multiple subscriptions can share ForwardedEvents. An exact record does not identify which subscription delivered it, prove accurate shared clocks, establish end-to-end latency, validate a translated query or make a Sigma rule Ready. Sysmon and other external telemetry are excluded.

## Tests and remaining lab acceptance

Fixtures test every source validation boundary, original-payload changes, permitted rendering additions, significant whitespace, ambiguity, caps, access failures, resource disposal, reader/channel/source drift, path safety and early public guards. Their positive matches are synthetic and supply no native forwarding evidence.

Server 2022/2025 CI under PowerShell 5.1/7 performs real read-only local collector/context queries, verifies a synthetic source marker is absent and checks output protection and unchanged collector settings. It does not create a subscription, generate an event or claim a successful cross-host arrival.

Before closing #368, test representative Windows 11, member server, DC and member CA sources against a dedicated isolated collector. Retain the real source probe and matched collector XML, actual reader and both contexts. Include delayed/missing delivery, disabled subscriptions, denied readers, duplicate events and configuration drift. Confirm both Events and RenderedText formats against native output. Validate query membership and subscription attribution separately; source/collector clock agreement and actual ingestion latency need independent evidence. See [WEF deployment](wef-deployment.md), [Microsoft WEF operation and formats](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection), and [Get-WinEvent query controls](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent).
