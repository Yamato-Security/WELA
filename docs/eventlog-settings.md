# Event-log sizes and retention modes

### Issue 379 coverage

Event-log sizing and retention changes are explicit per-channel controls with typed before/after evidence, mode preservation, and guarded recovery. Buffer size does not establish a retention duration, archive capacity, forwarding health, or absence of event loss.

`audit-filesize` and ordinary `configure` now use the same
`config/eventlog_profiles.json` definitions. `-Profile` continues to select
**advanced audit policy only**. Use the separate `-LogProfile` option with
`audit-filesize` or `configure-eventlogs` for channel buffer and retention settings.

```powershell
.\WELA.ps1 eventlog-profiles
.\WELA.ps1 audit-filesize -LogProfile wela-source-2.2.0
.\WELA.ps1 configure-eventlogs -LogProfile asd-source-2021-10 -DryRun -ResultsPath .\log-plan.json
# Increase undersized buffers; preserve existing modes and larger buffers.
.\WELA.ps1 configure-eventlogs -LogProfile asd-source-2021-10 -Auto -ResultsPath .\log-results.json
# Explicit source circular overwrite choice. Mode changes require this separate flag.
.\WELA.ps1 configure-eventlogs -LogProfile cis-v4-source -ApplyLogMode
# Explicit collector archive choice, only on an already provisioned collector.
.\WELA.ps1 configure-eventlogs -LogProfile asd-collector-archive-2021-10 -ApplyLogMode
# Deliberately resize to profile values, including shrinking larger buffers.
.\WELA.ps1 configure-eventlogs -LogProfile cis-v4-source -ResizeLogs -DryRun
```

`-ResizeLogs` and `-ApplyLogMode` are accepted only by `configure-eventlogs`.
Neither is implied by `-Auto`. The command supports the same `-DryRun`,
`-BackupPath` and `-ResultsPath` semantics as ordinary configuration. It requires
Windows and an elevated shell. It changes only size and the explicitly selected
mode: it does not enable or disable channels, install sensors, configure an audit
subcategory, write policy registry keys, or provision event forwarding.

| Log profile | Minimum sizes | Mode recommendation, applied only with `-ApplyLogMode` |
| --- | --- | --- |
| `wela-source-2.2.0` | Security and both PowerShell logs 1024 MiB; four AppLocker channels and firewall channel 256 MiB; Setup 32 MiB; remaining listed channels 128 MiB | Circular |
| `cis-v4-source` | Application, Setup, System 32 MiB; Security 192 MiB | Circular |
| `asd-source-2021-10` | Security 2048 MiB; Application and System 64 MiB | Circular (explicit WELA source-host choice, not an additional ASD prescription) |
| `asd-collector-archive-2021-10` | ForwardedEvents 2048 MiB | AutoBackup; collector only |

The WELA list also includes the previously audit-only BITS Analytic and DFSN Admin
channels. Missing role-specific channels remain explicit failed observations;
they are not silently removed from the result. Debug/analytic channels may impose
provider restrictions on changing their configuration while enabled. WELA reports
such a native failure and does not disable a channel or clear events to work
around it. Profile selection is not an assertion that every channel is installed
on every Windows role or edition.

The CIS values are from the reviewed **v4.0.0 Windows 11 Enterprise and Windows
Server 2022** editions, not the latest benchmark. This feature compares and changes
effective local channel values; it does not check the CIS requirement to configure
the corresponding Administrative Template policy or establish full baseline
compliance. GPO and MDM may restore different effective settings later. Source
identifiers and setting evidence are retained in JSON and audit CSV output.

Sizes are compared as integer bytes. One MiB is 1,048,576 bytes; profile targets are
rounded upward to the Windows 65,536-byte unit so rounding cannot undershoot a
minimum. The default comparison is `observed >= target`. Larger buffers are never
shrunk unless `-ResizeLogs` is explicit. Before writing, WELA rechecks state after
operator confirmation, preserving any newly enlarged buffer in minimum mode.
Windows does not provide an atomic compare-and-set for channel settings, so a
later concurrent writer remains outside this guarantee. Changing retention or
shrinking a buffer can affect event availability; review the dry run and storage
requirements before opting in.

`Circular` overwrites older events as the active buffer fills. `AutoBackup`
archives a full log and starts a new active log. `Retain` keeps existing events
and can discard incoming events when full. Audit output shows observed and
recommended modes separately from size compliance; omitting `-ApplyLogMode`
does not claim that a mismatching existing mode was corrected.

**Retention days remain Unknown.** A capacity setting does not establish event
rate, archive survival, or a retention period. For collectors, first configure
and verify subscriptions, forwarding, archive ACLs, available disk space,
capacity alerts, and backup/move procedures. Archive files accumulate: this
feature neither deletes them nor manages their age. A disabled channel remains
disabled, and no event-production or Sigma-coverage increase is claimed.

## Results and failures

The audit reads `Get-WinEvent -ListLog` live. Missing channels, access denied and
other unreadable state stay explicit; they are never replaced by documentary
Windows defaults. The CSV contains exact observed bytes, minimum and rounded
target bytes, size status, observed/recommended modes, mode status, channel
enabled state, source evidence and any read diagnostic. Access failures are not
misreported as missing channels. Displaying MiB does not round the compliance
decision.

Configuration uses the shared runner: journal before mutation, native exit-code
checks, immediate read-back, and a final drift check. Missing/unreadable channels,
ineffective changes and drift produce failed/overridden results and a nonzero
overall exit code while other selected channels are assessed. Successful size
configuration leaves no size warning for the same selected profile. Retention
warnings remain when the operator has not requested mode changes. `-DryRun`
performs no native setter calls and creates no recovery journal; an explicitly
requested JSON report may still be written.

## Recovery

Use a new protected `-BackupPath` and save the result JSON beside it. Do not use a
journal to overwrite a later intentional administrator or GPO change. For each
channel that needs recovery, review its current state and the latest journal
entry with `Phase: ImmediatePreWrite`: that record stores the fresh byte count and
mode observed immediately before the attempted write. The earlier runner entry
records the initial observation. A journal entry alone does not prove a successful
write; consult the result and live state. `BeforeWrite` is also in each result.

From an elevated shell, restore only the reviewed settings with `wevtutil sl`:

| Previous property | Restore arguments |
| --- | --- |
| Maximum size | `/ms:<Before.MaximumSizeInBytes>` |
| Circular | `/rt:false /ab:false` |
| AutoBackup | `/rt:true /ab:true` |
| Retain | `/rt:true /ab:false` |

Check the native exit code and read back the channel afterward. Review shrinking
or changes to event overwrite behavior first. Restoring a size or mode does not
recover overwritten records; WELA does not clear logs or delete archive files.
For a failed write, the original settings may already remain in place. This is a
manual per-channel procedure, not an automated rollback or complete log backup.

## Sources and validation

- [Microsoft wevtutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)
  documents byte sizing, 64 KiB units, retention and auto-backup flags.
- [ASD Windows event logging and forwarding (October 2021)](https://www.cyber.gov.au/business-government/detecting-responding-to-threats/event-logging/windows-event-logging-and-forwarding)
  provides the source buffer values and separate collector/archive guidance.
- [CIS Microsoft Windows benchmark catalog](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
  provides the benchmark access point; the values implemented here are the
  historical v4.0.0 editions reviewed for issue #379, Event Log Service settings.

`tests/EventLogSettings.Tests.ps1` uses safe channel/native fixtures and temporary
journals. It checks audit/configure agreement, preservation, explicit resize/mode
choices, rounding, missing/denied reads, concurrent growth, false-success writes,
journal failures and drift. Windows CI also runs
`tests/EventLogSettings.Windows.Tests.ps1`, which reads real channels and verifies
missing-channel handling without changing machine policy. Both run in Windows
PowerShell 5.1 and PowerShell 7. Real mutating behavior and ingestion still require
isolated Windows source/collector validation; these tests do not claim it.

Release packaging already includes the complete `config`, `modules` and `scripts`
directories. Keep them beside `WELA.ps1`, including the new JSON and module.
