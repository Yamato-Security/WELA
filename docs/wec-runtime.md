# Typed local WEC runtime observations

`wec-runtime` reads explicitly selected local Windows Event Collector subscriptions through `EcGetSubscriptionRunTimeStatus` in `Wecapi.dll`. It reports numeric activity and errors, UTC error/retry/heartbeat timestamps, and bounded per-source observations without parsing localized `wecutil gr` labels. It never creates, changes, retries or deletes subscriptions, starts services, configures listeners/firewalls, or generates events. Sysmon queries are excluded.

```powershell
# Native 64-bit Windows PowerShell 5.1 or PowerShell 7; use an authorized collector reader.
./WELA.ps1 wec-runtime -WecRuntimeId 'Security-Baseline' -ResultsPath .\runtime.json
./WELA.ps1 wec-runtime -WecRuntimeId 'Security-Baseline','Security-Suspect' -WecRuntimeMaximumSources 64
```

Supply 1–32 unique exact subscription IDs. The source limit is 1–512 per subscription (default 128); reaching a known larger inventory records the actual reported count, queries only the selected limit and makes the observation Partial. The native adapter also bounds buffers to one MiB, string lengths, source inventory to 4096 entries and buffer-resize retries. It imports only the runtime read API. IDs and report options are rejected on unrelated commands before profile dispatch. This read-only command does not accept Auto, DryRun or configuration options.

The selected definition is read before and after collection using native XML. Its exact subscription identity, explicit enabled/type fields and native QueryList must be readable. DTDs, malformed queries and Sysmon/EMET are rejected through the existing shared parser. Full normalized XML comparison detects definition changes during the observation. A changed source list, definition, actual host context or reader identity prevents a complete result. This is a sequence of observations, not an atomic snapshot or a guarantee against an intervening delete/recreate with an identical definition.

Each report records actual Windows computer/build/role context and the reader's SID, name, authentication type, impersonation level and group SIDs before and after collection, plus collection start/end UTC. Error text remains localized evidence; numeric native values determine the structured fields. The local APIs' authorization decides whether a read succeeds; administrator membership alone is not reported as proof of effective access.

## Read the fields correctly

| Field | Meaning |
| --- | --- |
| `Status=Observed` | All required reads and consistency checks completed. It is not a healthy-delivery verdict. |
| `Status=Partial` | Some runtime data exists, but a property failed, a cap was reached or evidence changed. Retained fields remain individual observations. |
| `Status=Unknown` | A verified local context/definition or runtime observation could not be established. |
| `Subscription.Activity` | Native enum 1 Disabled, 2 Active, 3 Inactive or 4 Trying. Unknown future values retain their number and uncertainty. |
| `Fields.LastError.Value` | The subscription/source's reported UInt32 error. `Fields.*.ErrorCode` separately records failure of the API read itself. |
| Optional timestamps/messages | Native null or zero FILETIME is NotAvailable. Invalid timestamp ranges are Unknown. Valid FILETIMEs become UTC strings, with the original integer retained. |
| `SourceInventory` | For source-initiated subscriptions, sources heard from within the past 30 days; the list persists across collector reboot. For collector-initiated subscriptions, configured sources. Neither is a current connection count. |

Disabled, Inactive, Trying and a nonzero reported LastError can all be successfully **observed**. Exit 0 means observation completeness only; unknown/partial subscriptions cause exit 1. There is no aggregate healthy or connected-source count. An Active subscription or heartbeat does not establish event arrival, successful XPath selection, backlog size, transmission latency, synchronized clocks or Sigma readiness. `ReadyRuleCredit` stays 0. Use the separate [exact WEF arrival verifier](wef-arrival.md) for a source probe's presence on the collector.

Existing `wec-collector` and `retention-health` JSON inventories gain a separate `TypedRuntime` object while retaining their original `Runtime.Raw` localized evidence and unverified delivery fields. Source-only WEF inventory does not query a remote collector. Their existing configuration/retention exit semantics remain unchanged; examine each `TypedRuntime.Status` for observation completeness. The dedicated command uses the exit behavior above.

Output is optional and must be a new file under an existing local fixed-drive directory, without UNC/device/stream or reparse paths. Relative paths follow the PowerShell location. UTF-8 JSON is created exclusively so existing reports cannot be overwritten. Choose an operator-controlled directory; the report may contain source names, account/group identifiers and subscription XML. The command does not alter the output parent's ACL.

## Validation and remaining acceptance

Fixtures exercise the actual EC_VARIANT buffer decoder, unsigned errors, Unicode, invalid pointers/types/counts, nulls, UTC fractional timestamps, caps, failures, drift, source-history semantics, raw-evidence preservation, JSON output and early CLI guards. No live subscription is touched by those fixtures.

The Windows workflow separately requires explicit `-AllowDisposableSubscription` and GitHub-hosted disposable Server 2022/2025 context. It temporarily starts Wecsvc when needed, creates one uniquely named **disabled** subscription with no real source identity, tests actual typed reads and missing-ID failure, and removes only the owned subscription after checking its unique description. It independently restores Wecsvc state/startup and checks the original subscription inventory. It creates no listener, firewall rule, domain membership or source endpoint. Native CI must pass before claiming the real adapter validated.

Connected source states, nonempty source history and real heartbeats/errors from Windows 11, member servers, domain controllers and ADCS remain deployment-lab acceptance. Event delivery and storage/retention guarantees are separate tests.

Primary references: Microsoft's [runtime API](https://learn.microsoft.com/en-us/windows/win32/api/evcoll/nf-evcoll-ecgetsubscriptionruntimestatus), [runtime property meanings and 30-day source history](https://learn.microsoft.com/en-us/windows/win32/api/evcoll/ne-evcoll-ec_subscription_runtime_status_info_id), [activity enum](https://learn.microsoft.com/en-us/windows/win32/api/evcoll/ne-evcoll-ec_subscription_runtime_status_active_status), [runtime sample and nullable fields](https://learn.microsoft.com/en-us/windows/win32/wec/displaying-the-status-of-an-event-collector-subscription), and [SDK ABI/constants](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/EvColl.h).
