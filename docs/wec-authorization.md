# Reviewed WEC source authorization

`wec-authorization` plans and applies the explicit source SID allow list of one **already disabled**, existing source-initiated HTTP/native-event subscription. This supplies the authorization update missing from the create-only collector command, query/description updater and separate Enabled transition. Related to #368; built-in Windows only, with no Sysmon.

```powershell
# Invoke the PowerShell script directly when supplying an array of SIDs.
.\WELA.ps1 wec-authorization -WecAuthorizationId 'Reviewed subscription' `
  -WecAuthorizationSourceSid 'S-1-5-21-111-222-333-1234','S-1-5-21-111-222-333-1235' `
  -WecAuthorizationOutputPath C:\Evidence\authorization-plan

# Review plan.json, including its complete original XML and desired source list.
# Retain its PlanHash from manifest.json before applying those exact bytes.
.\WELA.ps1 wec-authorization -WecAuthorizationAction Apply `
  -WecAuthorizationPlanPath C:\Evidence\authorization-plan\plan.json `
  -WecAuthorizationPlanHash '<reviewed SHA256>' `
  -WecAuthorizationOutputPath C:\Evidence\authorization-apply
```

Plan reads native configuration and writes review artifacts. Apply takes the subscription and desired list only from the reviewed plan. Both require a new private evidence directory on a local fixed drive. The actual elevated, non-impersonated reader, supported patched Server 2022/2025 standalone/member host, running Wecsvc/WMI/EventLog services, destination channel settings and implementation sources are observed and bound. No service is started, subscription enabled, channel changed or AD membership modified. Unknown options, mixed Plan/Apply inputs, `-Auto`, `-DryRun` and `-WhatIf` are refused; use Plan for review.

The desired list contains 1–32 unique canonical `S-1-5-21-A-B-C-RID` strings with native-range subauthorities. Order is normalized; duplicate SIDs, aliases, arbitrary SDDL, null/empty/default authorization and non-domain/certificate settings are refused. The existing descriptor must already be the same supported explicit allow-list form. WELA neither resolves these strings nor verifies that they identify domain computer accounts or groups. Obtain and independently verify intended identities and group membership before review. Adding a SID can broaden future authorization; removing one entry does not establish that a machine lacks access through another allowed group.

Apply checks the complete original definition and current context, flushes a pending receipt, opens only an existing native subscription and uses one `EcSubscriptionAllowedSourceDomainComputers` setter followed by save. The native adapter rechecks disabled/source-initiated state and selected native fields through a fresh handle. Native readback must match the desired list while all other observed XML fields, actual token, services and destination settings stay unchanged. Matching authorization returns `AlreadyMatches` without a save. Successful changes report `AuthorizationChangedAndVerified`; failures before save report `Refused`. Once save has been attempted, incomplete readback or preservation reports `SaveAttemptedUnverified` and retains available native after-XML.

An enabled subscription is refused, including a no-op request. Use the separately reviewed [Enabled transition](wec-state.md) when an intentional interruption or activation is required. To restore an authorization list, make a fresh plan against the current disabled definition using the original retained SIDs. There is no automatic rollback or native compare-and-swap: another administrator can race the pre-save observations. Coordinate changes and inspect retained evidence after partial results. Plan hashes check consistency and do not authenticate an untrusted evidence author.

The native CI fixture creates one uniquely named disabled subscription with inert SIDs, exercises public no-op/add/remove/restore, wrong-hash/stale/enabled refusals and a native fresh-handle drift check, then verifies original subscription inventory, service startup/state and complete channel restoration. Temporary service/channel changes belong only to explicitly opted-in disposable fixtures. These tests do not resolve or authenticate a source, change AD groups, verify forwarding or bookmarks, or award Sigma readiness credit.

Microsoft documents the [authorization property](https://learn.microsoft.com/en-us/windows/win32/api/evcoll/ne-evcoll-ec_subscription_property_id), [source-initiated subscription settings](https://learn.microsoft.com/en-us/windows/win32/wec/creating-a-source-initiated-subscription), [existing-only open flags](https://learn.microsoft.com/en-us/windows/win32/api/evcoll/nf-evcoll-ecopensubscription) and [activation on saving enabled subscriptions](https://learn.microsoft.com/en-us/windows/win32/api/evcoll/nf-evcoll-ecsavesubscription).
