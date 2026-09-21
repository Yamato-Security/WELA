# Reviewed event-log size and retention recovery

`eventlog-recovery` restores the size and retention mode immediately before one completed WELA profile operation. It supports administrative and operational channels in the bundled event-log profiles on reviewed Windows 11 / Server 2022 and 2025 builds. This is part of issues #379 and #365; it does not recover records already lost.

Use the original `before.jsonl` and final results from `configure-eventlogs` or the same profile helper used by `configure`. The selected result must be `Applied`, with both the initial and `ImmediatePreWrite` journal entries and matching final `BeforeWrite`. Failed, overridden, incomplete, legacy scalar writes and unexplained changes require manual investigation. Other journaled controls are not restored.

```powershell
./WELA.ps1 eventlog-recovery -EventRecoveryJournalPath C:\Evidence\original\before.jsonl `
  -EventRecoveryOriginalResultsPath C:\Evidence\original-results.json `
  -EventRecoveryLog ForwardedEvents -EventRecoveryOutputPath C:\Evidence\recovery-plan

# Inspect plan.json: current and original sizes, modes, channel guard and consent flags.
# Supply the exact PlanHash shown by Plan after reviewing that file.
./WELA.ps1 eventlog-recovery -EventRecoveryAction Restore `
  -EventRecoveryPlanPath C:\Evidence\recovery-plan\plan.json `
  -EventRecoveryPlanHash '<reviewed SHA256>' -EventRecoveryOutputPath C:\Evidence\recovery-run `
  -EventRecoveryAllowShrink -EventRecoveryAllowRetentionChange
```

The last two switches are separate consent for the effects actually identified by the plan. Omit them when inapplicable. **Shrinking can discard existing events.** Changing to Circular allows older records to be overwritten; changing to Retain can discard incoming records when full; leaving AutoBackup stops automatic archival. Review storage and recovery requirements before consenting. Plan writes review evidence but changes no Windows settings. Restore does not export or clear logs, restore an archive, alter channel enablement/ACL/path/provider settings or restart services.

Each output must be a fresh directory on a local fixed drive, with an existing parent. Evidence is protected for the current operator, Administrators and SYSTEM. The plan is bound to the actual current host/MachineGuid, operator logon, original input bytes and implementation/catalog hashes. Use the same checkout and elevated operator logon for Restore. Winmgmt and EventLog must already be running; host observations use the existing reviewed-build gate. The original version-1 journal records only historical ComputerName: current host bindings and hashes do not authenticate that history.

The plan is rebuilt from original evidence on Restore. Minimum-size writes are checked against the immediate-prewrite size so an independent increase during prompting is preserved. An unexplained larger final size is refused. Current size/mode/enable state must match the confirmed post-configuration state. Current channel path, ACL, isolation, type, owning provider and classic-log flag are captured when planning and must remain unchanged. Live event count and EVTX file allocation are intentionally not treated as configuration guards.

Restore flushes a Pending receipt before one fixed local `wevtutil sl` operation, rechecks the inputs and current channel, changes only the required size/mode arguments, and records final native readback. There is no atomic compare-and-set in this interface. A concurrent policy refresh or writer can still intervene, and verified values do not prove persistence.

`RestoredAndVerified` means the requested size/mode and preserved configuration matched during readback. `Refused` means no native write was attempted. `RestoreAttemptedUnverified` means a write may have partly succeeded; inspect the Pending receipt and any after-state evidence before further action. Automatic rollback and replay against the already-restored state are refused. A fatal evidence-write error may leave only a Pending receipt; keep it for investigation.

The Windows fixture uses genuine public configuration of the disposable runner's ForwardedEvents channel, then public planning, consent refusal, actual drift refusal, restoration and replay refusal. It restores the original channel configuration and compares every original audit mask. Matrices cover Server 2022/2025 and PowerShell 5.1/7; the test proves configuration behavior, not historical record preservation, achieved retention, forwarding or Sigma readiness. Sysmon is excluded.

Reference: [Microsoft wevtutil size, retention and auto-backup options](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil).
