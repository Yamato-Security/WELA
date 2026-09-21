# Recover Windows PowerShell transcription policy

`transcription-recovery` reviews and restores the two machine values changed by one completed `powershell-transcription -TranscriptionAction Configure` run. It requires that run's original `before.jsonl` and final JSON result, exactly one `Applied` control named `PowerShellTranscription/CisV4L2`, and current policy/directory observations that still match its final `After` evidence. Status, control, target and registry-type discriminators require actual strings; schema and outcome counters require integers. Boolean values cannot stand in for those fields. Failed, partial, skipped and already-compliant configuration records require manual review.

```powershell
./WELA.ps1 transcription-recovery -TranscriptRecoveryAction Plan `
  -TranscriptRecoveryJournalPath C:\Recovery\original\before.jsonl `
  -TranscriptRecoveryOriginalResultsPath C:\Recovery\original-result.json `
  -TranscriptRecoveryOutputPath C:\Recovery\new-plan

# Review every step in plan.json, including RequiresTemporarySuspension.
$reviewedHash = (Get-FileHash C:\Recovery\new-plan\plan.json -Algorithm SHA256).Hash.ToLowerInvariant()
./WELA.ps1 transcription-recovery -TranscriptRecoveryAction Restore `
  -TranscriptRecoveryPlanPath C:\Recovery\new-plan\plan.json `
  -TranscriptRecoveryPlanHash $reviewedHash -DryRun `
  -TranscriptRecoveryAllowTemporarySuspension

./WELA.ps1 transcription-recovery -TranscriptRecoveryAction Restore `
  -TranscriptRecoveryPlanPath C:\Recovery\new-plan\plan.json `
  -TranscriptRecoveryPlanHash $reviewedHash `
  -TranscriptRecoveryOutputPath C:\Recovery\new-attempt `
  -TranscriptRecoveryAllowTemporarySuspension -Auto
```

Omit `-TranscriptRecoveryAllowTemporarySuspension` when the reviewed plan does not require it. `-Auto` accepts the ordinary confirmation; it never supplies suspension consent. `DryRun` validates all bindings and consent, returns the proposed steps and creates no directory. Plan and real Restore require new private output directories. All evidence and transcript directory paths must be literal absolute paths on local fixed drives. UNC paths, mapped drives, alternate streams and observed reparse components are rejected.

## Supported restoration and ordering

The target is the existing shared machine registry key `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription`. The command supports original `OutputDirectory` REG_SZ values or absence, and original `EnableTranscripting` DWORD `0`, DWORD `1`, or absence. Other original types and values require manual recovery. Both Registry64 and Registry32 must agree. Recovery retains the existing key, removes only values that were originally absent, and never deletes policy subtrees.

When the original enablement was DWORD `0`, recovery restores that disabled state before changing the destination. If a destination change is followed by restoring DWORD `1` or removing the enablement value, the plan requires explicit temporary suspension: write DWORD `0`, restore the destination, then restore the original enablement or absence. An originally absent destination is supported only with original DWORD `0`; enabled/default-user destinations require manual recovery.

**Temporary suspension can leave machine transcription disabled.** By supplying `-TranscriptRecoveryAllowTemporarySuspension`, you accept that a write error, drift refusal or terminated process after the disable step and before final restoration can leave `EnableTranscripting=0`, even when the recovery target enables transcription. There is no automatic rollback or re-enable. A handled failure reports an incomplete attempt and stops subsequent writes; a terminated process may leave only pending/confirmed receipts without a final result. Inspect those receipts and the current native policy, verify the destination, and manually recover the intended enablement before relying on automatic transcription again. Do not re-enable blindly with an unverified destination.

Computer policy takes precedence over user policy, and policy-enabled transcription applies to PowerShell sessions. Removing a machine value can expose user/default policy; the command restores the recorded registry state without asserting session adoption. Manual `Start-Transcript` remains possible when automatic policy transcription is disabled. [Microsoft Windows PowerShell policy documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings?view=powershell-5.1). `HKLM\SOFTWARE\Policies` is shared across the registry views; recovery writes through Registry64 once and verifies both observations. [Microsoft WOW64 registry documentation](https://learn.microsoft.com/en-us/windows/win32/winprog64/shared-registry-keys).

Existing sessions are not stopped or restarted. Transcript files, their ACLs, shares, retention, collection, module logging, script-block logging, invocation-header preferences, current-user policy and all unrelated PowerShell policy values are preserved. The command inventories the other machine/current-user PowerShell policy tree with explicit bounds and stops when it changes.

## Evidence and failure handling

The reviewed plan binds original file hashes, the exact current host/MachineGuid and OS context, the elevated primary-token user/group/logon observations, current implementation hashes, both registry views, and the old/new directory observations. Restore verifies the separately supplied plan hash and independently rebuilds the plan from its original evidence and current observations. It checks those bindings after the prompt, before each write, during readback and at completion. A changed directory, policy, reader, source, plan or implementation stops the run.

Version-1 Configure journals record only the historical `ComputerName`. Current MachineGuid/logon/code bindings do **not** establish historical identity or authenticate supplied records. Hashes establish consistency. Keep original evidence and the reviewed hash under administrator control, review the authoritative GPO/MDM policy separately, and do not treat local registry restoration as proof of policy ownership or persistence.

Each mutation has a flushed, new `NNN-pending.json` receipt written before it and a separate `NNN-confirmed.json` only after verified readback. `result.json` contains actual observed final policy and confirmed steps. A pending receipt without confirmation is an uncertain step; inspect current native policy and preserve all receipts before manual recovery. A write may have succeeded even when its readback/receipt failed. Failed attempts and replay after a completed restore are refused by the original final-state guard; this command does not resume partial attempts or accept a new baseline silently. Failure to persist the result fails outward while existing evidence remains.

These are bounded point-in-time checks, not an atomic registry/filesystem lock. Another administrator or policy refresh may change state after a check. Private output guards observe ACL and directory identity metadata; they do not provide adversarial filesystem locking or central storage authorization proof.

## Validation scope

Portable tests exercise typed restoration, absent values, ordering, consent, preview, unsupported history, duplicate JSON, plan/source/host/directory/policy drift, prompt-time races and partial failures. The explicitly gated disposable native matrix targets Server 2022/2025 with Windows PowerShell 5.1 and PowerShell 7 as WELA hosts. It performs actual public Configure/Plan/Restore, checks native typed values and preserved policy, captures receipts, tests real drift refusal, and restores the fixture's exact original policy in `finally`. A fresh Windows PowerShell 5.1 session checks a benign transcript marker at the restored private local destination. Artifacts retain that fixture evidence and `cleanup.json`; PowerShell 7 remains only a WELA host.

`Restored` means the selected typed registry values passed final verification. Production transcript generation, existing/future session behavior, other identities, client/DC roles, central read/modify authorization, collection and retention remain separate validation. The report grants `SigmaEvtxCredit=0`; transcript text is separate from 4103/4104 EVTX. This advances recovery for [issue #376](https://github.com/Yamato-Security/WELA/issues/376) without completing its central authorization/ingestion acceptance.
