# Reviewed changes to a disabled WEC subscription

Related to #368. The existing `wec-collector` create workflow continues to preserve every different existing subscription. The separate `wec-update` command can change only the query and description of one **already disabled**, source-initiated HTTP/native-event subscription using Windows Event Collector APIs. It never creates, replaces, deletes, enables or pauses a subscription. Sysmon is excluded.

```powershell
.\WELA.ps1 wec-update -WecUpdateId 'Reviewed native subscription' `
  -WecUpdateSourceSid 'S-1-5-21-111111111-222222222-333333333-1234' `
  -WecUpdateQueryPath C:\Review\query.xml -WecUpdateDescription 'Reviewed account events' `
  -WecUpdateOutputPath C:\Evidence\new-plan
# Review plan.json: full original XML, desired query/description, host/reader and implementation hashes.
# Record the PlanHash from this planning result after reviewing the exact file bytes.
.\WELA.ps1 wec-update -WecUpdateAction Apply `
  -WecUpdatePlanPath C:\Evidence\new-plan\plan.json `
  -WecUpdatePlanHash '<reviewed 64-character lowercase SHA256>' `
  -WecUpdateOutputPath C:\Evidence\new-apply
```

Both actions require new private directories on local fixed drives with existing parents. Description is mandatory for planning; an explicitly empty string clears it. Source SIDs must match the existing narrow authorization exactly. The query parser accepts explicit built-in Windows channels and structural QueryList syntax; Windows validates the saved query. The actual local Server 2022/2025 collector, reader/token and running Wecsvc are observed. Standalone servers can review disabled subscriptions; no source connectivity is implied. No host/build overrides, service changes or remote collectors are supported.

The reviewed plan binds the complete original XML, explicit desired values, actual collector/reader/service context and implementation hashes. Apply verifies the separately supplied plan SHA256, strict JSON schema, native channel/query scope, complete original definition and fresh context. A protected pending receipt is flushed and read back before mutation. The native handle uses `EC_OPEN_EXISTING`, reads disabled/query/description again, sets only `EcSubscriptionQuery` and `EcSubscriptionDescription`, then saves. Final readback checks the requested values and all remaining observed XML. Already matching values cause no save.

Concurrent changes, enabled subscriptions, unsupported definitions, denied reads and changed plans fail rather than broadening scope. If save is attempted but fails or readback differs, the manifest says `SaveAttemptedUnverified`; no automatic rollback can overwrite an intervening administrator change. Preserve the receipt and inspect the actual subscription. Restoring original values requires a fresh plan against its current state using the original recorded query/description. Windows exposes no compare-and-swap or subscription lock here: the pre-save checks narrow but cannot eliminate a concurrent administrative write between observation and save. Coordinate a maintenance window; hashes are consistency checks, not signatures or authenticated approval.

The subscription remains disabled, and authorization, destination, delivery, locale, transport, ReadExistingEvents and other observed settings must remain unchanged. This first version deliberately requires disabled state: Microsoft documents that saving an enabled subscription activates it. Active-source delivery and bookmark continuity require separate lab acceptance before extending that scope. A successful disabled update grants **zero Sigma readiness credit** and proves neither delivery nor retention.

Tests include malformed/duplicate JSON, stale plans, changed context, unexpected enablement, preservation failure, native error, false success, idempotence and pending receipt ordering. Disposable Server 2022/2025 × Windows PowerShell 5.1/PowerShell 7 CI creates one unique disabled subscription with no real source, changes and restores query/description through the public command, rejects the stale plan, verifies other properties and restores subscription inventory plus original Wecsvc state/startup. It does not validate active sources or bookmarks.

References: [existing-only handles](https://learn.microsoft.com/en-us/windows/win32/api/evcoll/nf-evcoll-ecopensubscription), [subscription properties](https://learn.microsoft.com/en-us/windows/win32/api/evcoll/ne-evcoll-ec_subscription_property_id), [save/activation semantics](https://learn.microsoft.com/en-us/windows/win32/api/evcoll/nf-evcoll-ecsavesubscription), [Microsoft SDK ABI definitions](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/EvColl.h).
