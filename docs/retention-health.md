# Retention, archive and forwarding health evidence

`retention-health` reads local native Windows event logs and exports a console summary, JSON and self-contained HTML. It separates source/collector buffers, observed event boundaries, archive policy declarations, local archive evidence and collection/time diagnostics. It does not configure Windows, contact remote hosts, upload logs, clear logs, trigger rollover or test recovery. Sysmon and external telemetry channels are excluded.

```powershell
# No configuration or archive declaration is required for a local source report.
./WELA.ps1 retention-health -ResultsPath source-health.json -HtmlPath source-health.html

# Copy and edit config/retention-collector.example.json for a collector.
./WELA.ps1 retention-health -RetentionConfigPath collector-config.json -ResultsPath collector-health.json -HtmlPath collector-health.html

# Compare only with a trusted earlier report from this same computer and role.
./WELA.ps1 retention-health -RetentionConfigPath collector-config.json -RetentionPreviousPath previous-health.json -ResultsPath latest-health.json
```

Use distinct configuration and report filenames; report outputs are intentionally written only to the explicitly selected paths. Run with read access to the selected logs. Access denied, missing logs and native query failures remain visible; they do not erase successful observations from other channels. Exit 0 means the requested observations were collected, **not** that retention or forwarding is healthy. Exit 1 reports partial/unavailable evidence or an export/input failure. `-DryRun`, configuration switches and unrelated command options are rejected because this command is already read-only.

## Select the assessment

The optional JSON uses `SchemaVersion: 1`, `Role: "Source"` or `"Collector"`, and 1–32 unique exact native `Channels`. The default is Source with Security, System and Application. The role is an operator declaration about this local assessment, not a discovery of remote topology or proof that the host is a dedicated collector. ForwardedEvents should be selected explicitly in a collector config.

| Setting | Default and limits | Meaning |
|---|---|---|
| `SampleWindowMinutes` | 60; 1–1440 | Historical TimeCreated window ending at the report's UTC timestamp. |
| `MaxEventsPerChannel` | 1000; 1–10000 | Maximum retained records used per rate/signal sample. One extra sentinel detects truncation. |
| `StaleAfterMinutes` | 60; 1–10080 | Review threshold for the last readable record's timestamp. This does not diagnose a backlog. |
| `ProjectionDays` | 30; 1–3660 | Explicit horizon for a conditional XML-byte scenario. |
| `SubscriptionIds` | Empty; up to 32 | Exact subscriptions to query locally on a Collector. No subscription is created or changed. |
| `Archive` | Omitted | Optional declaration and bounded local EVTX directory inventory; see below. |

## What the measurements establish

Each channel retains maximum buffer bytes, current logical log-file size, record count, oldest record number, full/enabled flags, mode and channel security descriptor where readable. These properties are local buffer settings/state, not archive capacity or proof of central retention. In particular, a preallocated log file's length is not the amount of retained event content.

Age uses the **first readable record in log order**, with the first/last native record, UTC TimeCreated, XML and localized message retained for review. It is not a scan for the global minimum timestamp. Clocks can change and forwarded events can arrive out of timestamp order. Future boundary timestamps produce an anomaly rather than a negative age; absent/denied data stays empty/unknown. Even an 800-day-old record does not prove a complete 18-month history, coverage of all required hosts/events, or recoverability.

The rate is the count of retained records in the specified **TimeCreated** window divided by that whole window in seconds. This is a timestamp density of retained records, not measured collector arrival throughput or a loss-free source generation rate. A query that reaches the cap reports a lower bound for the sampled window. Queries with no records report that observation; they cannot establish zero event loss or zero required storage. Clears, overwrites, disabled channels, clock errors and filters can all hide records.

The byte basis is `UTF8.GetByteCount(event.ToXml())`, excluding the separately rendered Message. The report includes measured XML bytes, average XML bytes per sampled record, the window, cap, sample count and projection days. The scenario is `sample XML bytes / window seconds × projection days × 86400`, assuming the retained-event rate/mix persists. Capped projections keep their lower-bound qualification under that assumption. Missing XML or timestamps prevent extrapolation. These bytes are **not** EVTX binary storage, filesystem allocation, compressed archive size, indexing/replication overhead, or available capacity. WELA does not divide buffer size by this estimate to claim a retention duration.

An optional previous report must have an earlier timestamp, matching computer name, schema, scope and declared role. Its values are imported operator evidence, not independently authenticated. Comparing readable oldest-record numbers can flag an advance/reset for review; it cannot establish whether rollover, clearing or another change caused it, how many events were lost, or whether they were forwarded first. An unchanged boundary also cannot prove continuity.

## Archive declarations and local evidence

The cited [ASD October 2021 guidance](https://www.cyber.gov.au/business-government/detecting-responding-to-threats/event-logging/windows-event-logging-and-forwarding) recommends at least 18 months of event retention and consistent accurate time across devices. The report records this source-specific reference separately from the operator's declaration and observed event data. It never claims achieved 18-month compliance.

```json
"Archive": {
  "DeclaredRetentionMonths": 18,
  "PolicyEvidence": "Approved policy/archive evidence reference; operator supplied",
  "Directory": "D:\\ReviewedEventArchives",
  "MaxFiles": 10,
  "ReaderSids": ["S-1-5-21-111-222-333-1234"]
}
```

`DeclaredRetentionMonths` can be null or 1–120. `PolicyEvidence` is descriptive, unverified evidence (maximum 4000 characters); it is not downloaded or executed. Omit/null `Directory` to record an external archive policy without inspecting storage. For local inspection, choose an existing regular directory on a fixed local drive. UNC paths, mapped network drives, device paths, wildcards, streams and reparse-point ancestry are refused. WELA does not mount external storage. External systems can integrate by supplying their policy/evidence reference and placing selected exported native EVTX files in a reviewed local directory outside this command.

Inventory is nonrecursive, filesystem-order and limited to `MaxFiles` (1–100); a sentinel reports truncation. Reparse files are skipped. Each selected file reports its logical length, file last-write timestamp and readable event boundaries separately. File timestamps do not substitute for event timestamps. Unsupported/non-native boundary channels are excluded; inspecting two records does not validate the complete content of an archive. Files with unreadable events retain the read errors; an inventory is not a restoration test or a proof of immutability.

Directory SDDL/ACEs are recorded, and exact ACEs naming each intended `ReaderSids` entry are shown. These are observations, **not** effective token access checks: group membership, deny precedence, privileges and individual file ACLs are not evaluated. Reader authorization, tamper resistance, external retention enforcement, complete archive coverage and recovery all remain unverified. No ACL, ownership, share or retention setting is changed.

## Forwarding, loss and time diagnostics

Selected collector subscriptions use the merged WEF XML reader and native `wecutil gs /f:xml` / `gr` read operations. Definitions, explicit enabled state, native QueryList filters and localized runtime output/errors are preserved. Unknown/unrecognized query scope remains unknown. The reporting command does not infer successful delivery from an enabled subscription or successful native exit. Source/collector operational logs are sampled for critical/error/warning records in the declared window; raw XML/messages retain their context.

Separate native Eventlog-provider samples retain Security 1101/1102/1104/1105/1108 transport-drop, clear, full, automatic-backup and processing-error indicators, plus System 104 clear indicators. A full/clear/error is useful review evidence; these samples do not calculate a complete loss total. Missing or capped diagnostics and zero observed indicators cannot establish absence of loss. Stale forwarded event timestamps can reflect source clocks, quiet sources or replay, so backlog and actual arrival latency remain Unknown pending correlated source/collector evidence.

Time evidence is limited to local `w32tm /query /status /verbose`, `/query /source` and `/query /configuration`. Native localized output and failures are retained without parsing English labels. These read operations do not change time sources or resynchronize clocks. Successful commands or an enabled service do not prove accurate time, source health or agreement between hosts; those statuses remain Unknown.

## Validation and remaining acceptance

Safe fixtures cover the public JSON/HTML path, cap arithmetic, exact XML-byte projections, denied/empty/future data, independent failure preservation, declared versus achieved archive retention, reader ACE uncertainty, native-only scope and previous-boundary comparisons. Windows PowerShell 5.1/PowerShell 7 CI exercises actual local source/collector reads, owned-directory ACL observation and self-contained exports without modifying Windows settings. New files are included by the existing release packaging of `scripts` and `config`.

Before closing issue #382, use an isolated multi-host lab to compare source/collector timestamps and actual event arrival, demonstrate the intended reader tokens can read/recover archived events, test rollover and recovery with known event sequences, measure real ingestion/storage growth under representative load and verify the external archive enforces its retention policy. Record missing-event, denied-read, time-skew, disabled-subscription, restart and recovery cases. This PR provides evidence collection; it does not supply those deployment acceptance results or increase Sigma coverage.

Primary references: [Microsoft WEF operational behavior and delivery formats](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection), [native source-initiated subscription validation](https://learn.microsoft.com/en-us/windows/win32/wec/setting-up-a-source-initiated-subscription), [Windows Time query tools](https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings), [Get-WinEvent ordering/query controls](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent), [Security log clear 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102), [Security log full 1104](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1104).

Selected subscriptions also expose [typed local WEC runtime observations](wec-runtime.md) as `TypedRuntime`, alongside unchanged raw native evidence. Partial or unknown runtime reads remain explicit; Active and historical source inventory do not establish event delivery, backlog or retention compliance.
# Issue 382 coverage

The retention report now keeps local buffer age, bounded event-rate projections, archive declarations, time-source observations, subscription runtime queries, and rollover boundaries as separate evidence. A buffer size or sampled record age never counts as central retention, archival capacity, forwarding health, or loss-free coverage. Collector operators must provide an explicit archive declaration and subscription IDs; unobserved delivery, access, and cross-host clock agreement remain `Unknown`.
