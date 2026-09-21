# Reviewed enable/disable of an existing WEC subscription

`wec-state` reviews and changes only the **Enabled** Boolean of one existing native source-initiated HTTP subscription to ForwardedEvents. It completes the local pause/resume configuration step around [disabled query updates](wec-update.md). Disabling interrupts collection; enabling and saving activates the subscription. Review the source authorization, query, ReadExistingEvents setting and collection impact before Apply. No subscription is created, replaced or deleted, and no listener, firewall, service, channel, source authorization or query is changed.

```powershell
# Native 64-bit Windows PowerShell 5.1 or PowerShell 7 on the collector.
./WELA.ps1 wec-state -WecStateId 'Reviewed native subscription' `
  -WecStateSourceSid 'S-1-5-21-111111111-222222222-333333333-1234' `
  -WecStateDesired Disabled -WecStateOutputPath C:\Evidence\disable-plan

# Review plan.json and record its PlanHash from the planning result.
./WELA.ps1 wec-state -WecStateAction Apply `
  -WecStatePlanPath C:\Evidence\disable-plan\plan.json `
  -WecStatePlanHash '<reviewed 64-character lowercase SHA256>' `
  -WecStateOutputPath C:\Evidence\disable-apply

# Resuming requires a fresh plan against the current definition:
./WELA.ps1 wec-state -WecStateId 'Reviewed native subscription' `
  -WecStateSourceSid 'S-1-5-21-111111111-222222222-333333333-1234' `
  -WecStateDesired Enabled -WecStateOutputPath C:\Evidence\enable-plan
```

Plan is the default and performs read-only native observations plus new evidence files. State is always explicit. Apply requires the reviewed file and separately supplied SHA256. `-Auto`, `-DryRun`, hypothetical host/role overrides and unrelated configuration options are rejected. An already matching state performs no native save: saving an enabled subscription could otherwise reactivate/retry it.

The actual collector must be a standalone or member Server 2022/2025 with Wecsvc already running. Enabling additionally requires ForwardedEvents already enabled; its observed configuration is included in the review/context guards. Explicit domain source SIDs must match its existing narrow authorization exactly; this does not prove those sources exist or can connect. Supported definitions use the existing strict native subscription parser: exact built-in channel filters, source-initiated HTTP5985, ForwardedEvents, a standard delivery preset, explicit content format/locale and ReadExistingEvents. Certificate/non-domain sources, arbitrary delivery properties and Sysmon/EMET are excluded. Dedicated domain/Kerberos deployment remains a separate [WEF configuration](wef-deployment.md) operation.

The reviewed plan binds complete original subscription XML, desired Boolean, actual host/build/role and operator identity/logon, service state and implementation hashes. Plan and Apply may run in separate processes in the same Windows logon; a different logon needs a fresh plan. Each operation also compares full native token statistics, including token/modification identifiers, to reject token or privilege changes during that operation. Hashes establish consistency, not authenticated approval or an untrusted evidence author's identity.

Apply uses `EC_OPEN_EXISTING` and requires the complete current definition to match its reviewed pre-state. A private Pending receipt is flushed and verified before mutation. Immediately before saving it rechecks evidence, source files, host/reader/token/service and full XML; a freshly opened native view also checks Enabled, query, description and authorization. The only property passed to `EcSetSubscriptionProperty` is `EcSubscriptionEnabled`. Readback requires the desired state and every other observed XML element to remain semantically identical, including native Delivery/EventSources expansion. Raw original/after XML is retained without rewriting it. A changing source inventory can therefore leave the configuration result unverified even when the requested Enabled value is observed.

Windows exposes no subscription lock, generation identity or atomic compare-and-swap. Concurrent administrators, source updates or an identical delete/recreate cannot all be excluded by these observations. Coordinate the operation on a quiescent subscription. The command makes no automatic rollback: reversing a state change requires another reviewed plan against the current definition. Failed saves or differing readback return `SaveAttemptedUnverified`, retaining the native error code and a best-effort post-failure definition/runtime observation. An activation failure can still persist Enabled; failure never implies rollback; retain the pending receipt and inspect actual Windows state before deciding what to do next. `NativeSaveAttempted` records whether the native save call was reached, including its failures. Pre-save refusals do not receive that flag.

Output must be a new directory under an existing local fixed-drive parent. UNC/device paths, streams and observed reparse points are rejected through the shared evidence-path helper. The new directory is restricted to the operator, SYSTEM and Administrators; existing paths and ACLs remain unchanged. Files use exclusive creation, flushed readback and SHA256 checks before the final manifest. These are sequential observations, not protection against a competing administrator. Reports contain sensitive source/host/account metadata. A missing final manifest means the evidence is incomplete.

`ReviewRequired`, `AlreadyMatches` and `StateChangedAndVerified` are configuration results. Separate bounded `RuntimeBefore`/`RuntimeAfter` objects reuse [typed native runtime observations](wec-runtime.md), capped at 32 sources; their Unknown/Partial statuses remain visible and do not become healthy-delivery claims. Active, heartbeat or an enabled setting proves neither event arrival nor uninterrupted collection. Bookmark continuity, backlog, transmission latency, source authorization effectiveness, retention and Sigma readiness remain unverified; `ReadyRuleCredit` is always zero. The command does not create an event or refresh a source.

Portable tests exercise stale plans, wrong hashes/types/authorization, duplicate JSON, unsupported queries, host/token/source drift, false native success, preservation/evidence failures, and idempotence. The gated disposable Server 2022/2025 × Windows PowerShell 5.1/PowerShell 7 fixture creates one uniquely owned subscription authorized to a fictional SID, uses the public CLI for actual enable/disable and idempotent transitions, checks complete preservation and stale-plan refusal, temporarily enables ForwardedEvents as a fixture prerequisite, then removes only the owned subscription and restores exact channel settings plus service state/startup. It creates no listener or real source. Native CI validates local state transitions only; connected Windows 11/member/DC/ADCS sources, actual event arrival, disable/resume gaps and bookmarks remain isolated multi-host acceptance for issue #368.

References: Microsoft [subscription property types](https://learn.microsoft.com/en-us/windows/win32/api/evcoll/ne-evcoll-ec_subscription_property_id), [existing-only open](https://learn.microsoft.com/en-us/windows/win32/api/evcoll/nf-evcoll-ecopensubscription), [access/open constants](https://learn.microsoft.com/en-us/windows/win32/wec/windows-event-collector-constants), [save activation/retry semantics](https://learn.microsoft.com/en-us/windows/win32/api/evcoll/nf-evcoll-ecsavesubscription) and [token statistics](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_statistics).
