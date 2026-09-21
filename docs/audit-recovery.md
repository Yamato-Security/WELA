# Guarded audit recovery

Related to #365. `audit-recovery` restores **explicitly selected** advanced audit subcategories and the typed `SCENoApplyLegacyAuditPolicy` value from a completed WELA configuration journal and its matching JSON results. Sysmon is out of scope. The three named logging switches below are also supported. Other journal controls remain manual recovery tasks.

```powershell
# Save results during the original configuration.
./WELA.ps1 configure -Profile wela-2.2.0 -BackupPath C:\Evidence\before -ResultsPath C:\Evidence\original.json
# Review a new plan (no policy changes).
./WELA.ps1 audit-recovery -RecoveryJournalPath C:\Evidence\before\before.jsonl -RecoveryOriginalResultsPath C:\Evidence\original.json -RecoveryControlId 'AuditPolicy/Process Creation' -RecoveryOutputPath C:\Evidence\review
# Preview; no output directory or policy writes.
./WELA.ps1 audit-recovery -RecoveryAction Restore -RecoveryPlanPath C:\Evidence\review\plan.json -DryRun
# Explicit restore, with per-control prompts; -Auto accepts these reviewed changes.
./WELA.ps1 audit-recovery -RecoveryAction Restore -RecoveryPlanPath C:\Evidence\review\plan.json -RecoveryOutputPath C:\Evidence\recovered
```

Only unique canonical GUID/name pairs with matching `Applied` final results are eligible. Failed, overridden, partial or unsupported writes require manual review. The plan is independently rebuilt from the original byte-hashed files; altered plans, sources, actual host identity or current post-write state block restoration. Paths follow the PowerShell location. Output directories must be on a local fixed drive: mapped network drives, UNC/device paths, alternate data streams and reparse ancestors are rejected before output creation. This restriction applies to output, not the existing journal/results input handling. New directories and files preserve earlier evidence; recovery writes have durable before-state receipts and immediate/final readback.

Exact masks return to their recorded previous mask. Minimum-mode restoration removes only the requested bits absent before WELA: before `0`, requested Success `1`, final `3` restores to Failure `2`, preserving the independent addition. Recovery cannot determine who changed a bit between observations and does not claim transactional protection from concurrent administrators or GPO.

Subcategory recovery requires enabled DWORD precedence. To restore precedence itself, explicitly select `Registry/HKLM:\SYSTEM\CurrentControlSet\Control\Lsa/SCENoApplyLegacyAuditPolicy` plus **every** journaled audit subcategory. Only prior DWORD 0/1 or value absence under the existing LSA key is supported. Precedence runs last, after all subcategories succeed and are checked again. Failed/declined recovery blocks it. No arbitrary registry paths, services, SACLs, CA restarts or NTLM settings are replayed.

Version-1 journals identify the historical host only by ComputerName. The review plan additionally binds the current MachineGuid and observed build/patch/join/role context. This does **not** prove historical image identity; use only your trusted original evidence. Hashes establish byte consistency, not signatures or authenticity. Reports describe point-in-time local restoration, not GPO persistence, generated events or Sigma readiness.

Tests cover minimum-mask truth tables, evidence/host/plan tampering, drift, ordering, partial failure, readback and idempotence. Explicitly gated disposable Server 2022/2025 CI exercises actual completed journals and exact audit-policy restoration under PowerShell 5.1/7, with independent safety restoration. Domain policy refresh and Windows 11/DC/ADCS deployment checks remain separate.

## Named logging DWORD recovery

The same Plan/Restore flow accepts exactly these additional `RecoveryControlId` values:

- `Registry/HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit/ProcessCreationIncludeCmdLine_Enabled`
- `Registry/HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging/EnableScriptBlockLogging`
- `Registry/HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging/EnableModuleLogging`

Each must have a matching completed `Applied` DWORD-1 write. Supported original states are DWORD 0/1 or value absence; strings, other integer values/types, incomplete writes, module-name lists, transcription settings, NTLM and arbitrary keys are refused. Recovery changes or removes only the selected value. **Existing keys are retained**, including keys created by the original configuration: `OriginalKeyExisted` reports that distinction. Missing current keys require manual review. This does not restore an entire PowerShell logging configuration or provide event/Sigma credit.

Planning records the native path plus bounded hashes of all other values, direct child names and owner/group/DACL. Restoration reopens existing native 64-bit HKLM SOFTWARE keys component by component without following registry links, checks those guards, then changes the selected value through the same held handle. Immediate readback and a fresh path reopen must agree. Inventories are bounded to 256 values/children, 64 KiB per value/security descriptor and 1 MiB total value data; unsupported inventories fail closed. No key, child, owner/group/DACL or SACL is intentionally modified by recovery. The guard observes owner/group/DACL, **not the SACL or descendant contents**.

The reviewed plan also binds current recovery implementation hashes; changed or previously loaded mismatched native code requires a new plan/process. Guards pin observations at recovery planning time; the original version-1 journal does not contain historical registry object identities or neighboring data. Native names are not durable identities. Repeated recovery reports `AlreadyRecovered` when the selected value is already at the reviewed target and guards still match, without claiming who restored it. Concurrent replacement with identical observations, change-and-change-back, and policy/admin writes cannot be excluded atomically. Use a quiet maintenance window; there is no automatic rollback after a failed post-write check.

Portable regressions exercise the three-value allowlist, typed/absent states, source/evidence tampering, neighboring-data drift, dry-run, receipts and idempotence. Gated native Server 2022/2025 runs under Windows PowerShell 5.1 and PowerShell 7 create real configuration journals for each switch from DWORD 0 and absence, verify value-only restoration and neighboring-data preservation, and restore the runner's original typed states. These are disposable local tests, not domain-policy persistence or Windows 11 deployment evidence.
