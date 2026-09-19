# Guarded audit recovery

Related to #365. `audit-recovery` restores **explicitly selected** advanced audit subcategories and the typed `SCENoApplyLegacyAuditPolicy` value from a completed WELA configuration journal and its matching JSON results. Sysmon is out of scope. Other journal kinds remain manual recovery tasks.

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
