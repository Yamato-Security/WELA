# DNS Server analytical logging

`dns-analytical` is a dedicated, opt-in adapter for `Microsoft-Windows-DNSServer/Analytical`. Audit is the read-only default. The existing `provider-packs` analytical entry remains manual-only; this command does not open the ordinary channel setter to arbitrary Analytical or Debug channels. Native Windows only; Sysmon is excluded.

```powershell
./WELA.ps1 dns-analytical
./WELA.ps1 dns-analytical -DnsAction Plan -DnsState Enabled -DnsRetention Retain
./WELA.ps1 dns-analytical -DnsAction Configure -DnsState Enabled -DryRun

# Read the plan and review the interruption, archive location and retention choice first.
./WELA.ps1 dns-analytical -DnsAction Configure -DnsState Enabled `
  -DnsRetention Retain -AllowDnsTraceReset -BackupPath C:\WELA-Recovery\dns-001 `
  -ResultsPath .\dns-configured.json

# An explicit stop also archives the stopped trace; it does not clear it.
./WELA.ps1 dns-analytical -DnsAction Configure -DnsState Disabled `
  -AllowDnsTraceReset -BackupPath C:\WELA-Recovery\dns-002
```

Use a 64-bit elevated Windows session on a reviewed server build with the DNS service already running. The actual role/build/patch context, provider GUID, channel links, Analytical type and event 257's exact `QNAME` string template are checked. Missing roles, services, manifests, fields or unknown state block changes. The command never installs DNS, starts a service, changes a zone, issues a DNS query or changes audit policy. Clients are outside this adapter's scope.

The built-in provider profile is `native-provider-packs-v1`; its catalog and pinned full-rule artifacts are validated. Their source identities and the implementation hashes are recorded. This is a DNS provider profile, separate from advanced audit `-Profile`/`-ProfileFile`. Dedicated DNS options are rejected on unrelated commands. Configure requires an explicit `-DnsState Enabled|Disabled`.

## Sizes and retention

Enabling uses a default 32 MiB minimum, a WELA optional floor rather than a Microsoft baseline requirement. `-DnsMinimumBytes` accepts 1 MiB–1 GiB, rounds upward to native 64 KiB units and preserves larger existing buffers. Disabling does not resize the buffer. ACL, registered trace path, provider and other observed settings are preserved.

`-DnsRetention Preserve` is the default. Explicit `Circular` permits oldest-event overwrite; `Retain` stops accepting new events when full. AutoBackup is outside this adapter's supported direct-channel modes. Neither mode proves a retention duration or complete collection. Microsoft's [DNS logging guidance](https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-logging-and-diagnostics) describes the tradeoffs and recommends monitoring logging load.

An enabled circular direct channel cannot be queried in the same way as an Operational log. A query failure in this state does not prove that logging failed. Microsoft documents [stopping a circular analytical channel before viewing/exporting its events](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-when-enabling-analytic-debug-event-log). This adapter reports configuration separately from native event generation.

## Consent, durable archives and failures

Every non-idempotent Configure requires `-AllowDnsTraceReset`, including stopping a running trace. Stopping creates a collection gap; enabling, resizing or changing retention can reset trace contents. `-Auto` only skips the ordinary confirmation and cannot supply reset consent. Dry-run requires Configure and writes neither recovery files nor channel settings.

Before a transition, the adapter creates a **new private recovery directory** under an existing operator-controlled parent and durably records `01-before.json`. It rechecks source/context/schema/channel state, stops the channel if necessary, verifies the stopped configuration and records `02-stopped.json`.

It then opens the registered local ETL through a stable native handle, refuses reparse points, non-fixed drives, remote paths and ambiguous stream/wildcard/control/trailing-dot-space paths and writer/delete sharing, and copies in 64 KiB blocks to a new `trace-before.etl`. `-DnsArchiveMaximumBytes` defaults to 1 GiB and accepts 1 MiB–4 GiB; an oversized trace blocks the reset rather than being truncated. File identity, length and SHA-256 are checked against source and archived bytes. `03-archive.json` distinguishes:

- `ArchivedBytes`: the complete bytes available in that stopped file were copied and read back with the same hash.
- `ObservedAbsent`: native `FILE_NOT_FOUND` was observed under existing local parents. No empty archive or hash is fabricated.
- Failure: inaccessible, locked, empty existing, oversized, changed or unsupported trace state. This cannot authorize a reset.

Both source and saved archive are revalidated immediately before the reset-capable native command. Readback must match the desired enable/size/retention values and preserved ACL/path/context. `04-applied.json` records that verified moment; `05-result.json` records final status and any later drift. New result paths resolve relative to PowerShell's current location, require unambiguous fixed-drive paths, and never overwrite existing evidence or write alternate data streams. The last source/archive recheck runs after the final context observation and immediately before the native reset call; it is not an atomic compare-and-reset operation.

If archival fails after a stop, the result is **Failed** and the trace remains stopped. Automatically re-enabling could destroy the very evidence that could not be archived. Recovery files and the observed after-state remain available; a failed/partial operation is never unconditional success. A successful repeat is AlreadyCompliant and performs no stop, archive or reset.

The archive establishes byte preservation at the recorded time, **not** EVTX validity, complete historic retention, continuity, forwarding or rule coverage. No compare-and-swap transaction exists against concurrent Event Log administration. Rechecks and stable archive handles narrow races; use an isolated change window. Later state changes are not prevented.

## Recovery

Read `01-before.json`, `03-archive.json` and the final result together. Preserve archived traces outside the live trace path, verify their hashes, and review the current native channel state. Never copy an old archive over an active log. Returning a size/retention/enable setting can itself reset the current trace: stop and archive that current trace first, then perform an explicitly reviewed restoration through the policy authority. This command preserves larger buffers and does not provide automatic shrinking or blind rollback.

The ordinary audit-policy recovery workflow does not interpret these dedicated DNS receipts. A receipt records observations and completed transitions; it is not authorization to overwrite later settings or evidence.

## Validation and remaining scope

Mocked tests cover explicit selection/consent, role/service/schema blockers, larger buffers and rounding, native failures, source/channel/trace/archive races, journal failures, typed absence, stopped partial states, final drift and public guards. The native workflow uses separate disposable Server 2022/2025 hosts for PowerShell 5.1 and 7. It creates the standalone DNS role and one unique authoritative `.test` zone, resolves only a unique name through `127.0.0.1`, and checks event 257 with the exact provider GUID, machine, unique `QNAME`, loopback addresses and successful authoritative A response in the stopped ETL archive. Raw ETL XML can contain an empty `System.Channel`; the fixture retains it unchanged and establishes channel provenance from the verified registered trace path plus the exact provider event/version-to-channel manifest link. A contradictory nonempty XML channel is rejected. A separate probe receipt records this distinction; it is not a backend field mapping or readiness claim. Native file fixtures verify streaming copies, locks, absence, empty files and caps.

The fixture restores exact channel configuration, verifies audit policies are unchanged, and removes only its owned zone/records. It requests removal of the feature it installed; a successful uninstall requiring a restart is recorded as pending disposal of the ephemeral GitHub runner, not complete live OS restoration. Native CI must pass before those cases are claimed as observed.

Production configuration does not generate a probe automatically. Windows 11/DC/CA behavior, populated production DNS workloads, recursive events 260/261, collection continuity and backend execution remain separate acceptance work. The pinned rules currently use `Microsoft-Windows-DNS-Server/Analytical`, while the observed native channel is `Microsoft-Windows-DNSServer/Analytical`; no silent alias rewrite or readiness uplift is applied. Every result retains `ReadyRuleCredit=0` and `GenerationReadiness=Unverified`.

Primary references: [DNS logging and event fields](https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-logging-and-diagnostics), [direct-channel query restrictions](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-when-enabling-analytic-debug-event-log), [wevtutil parameters and byte rounding](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil).
