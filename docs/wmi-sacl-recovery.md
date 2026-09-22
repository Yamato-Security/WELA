# Reviewed WMI namespace SACL recovery

`wmi-sacl-recovery` removes one explicit, parent-only success audit ACE proven to have been added by a completed `wmi-auditing Configure` operation. It advances #372 and #365 without closing their broader auditing and recovery acceptance work. Sysmon is excluded.

## Review and recover

Keep the trusted original backup `before.jsonl` and successful result JSON. Select the exact canonical namespace used by that operation. There must have been exactly one missing ordinary parent-only success ACE; inherited/inheritable additions, multiple additions, failed/partial operations, source-profile changes and a changed current descriptor require manual assessment.

```powershell
./WELA.ps1 wmi-sacl-recovery `
  -WmiRecoveryNamespace 'root\default' `
  -WmiRecoveryJournalPath C:\Evidence\original\before.jsonl `
  -WmiRecoveryOriginalResultsPath C:\Evidence\completed.json `
  -WmiRecoveryOutputPath C:\Evidence\recovery-review

# Review plan.json and obtain its SHA-256 independently before authorizing recovery.
$reviewedHash = (Get-FileHash C:\Evidence\recovery-review\plan.json -Algorithm SHA256).Hash.ToLowerInvariant()
./WELA.ps1 wmi-sacl-recovery -WmiRecoveryAction Recover `
  -WmiRecoveryPlanPath C:\Evidence\recovery-review\plan.json `
  -WmiRecoveryPlanHash $reviewedHash `
  -WmiRecoveryAllowAuditReduction `
  -WmiRecoveryOutputPath C:\Evidence\recovery-result
```

Both output directories must be new, local fixed-drive directories. `Plan` reads native state and writes evidence only. `Recover` reconstructs the plan from the original records, verifies its hash and requires explicit audit-reduction consent. It rejects unrelated CLI options, including `Auto`, `DryRun`, arbitrary registry settings and namespace inheritance switches. It never enables audit policy or starts services.

## Evidence and preservation

The result must contain one unique Applied namespace control whose typed target, before snapshot and desired definitions exactly match the journal. The current complete native descriptor must match its recorded After state. The proof checks all original descriptor properties and SACL-entry multiplicities, permits only the original SACL-present transition, and identifies one previously absent explicit success ACE. Unknown added-ACE fields, duplicate matching additions and propagation-request control flags are refused; unrelated existing entries remain opaque and preserved.

Review plans bind the actual computer/build/role/MachineGuid, current logon, group attributes, full privilege inventory, all 59 audit masks, typed precedence, running services, PowerShell executable and installed implementation hashes. Recovery checks these values and the original records again before and after writing. Only the selected ACE is removed from the held native descriptor. The provider request omits owner, group and DACL updates; every retained field and remaining ACE order must match native readback and an independent reopened observation. The temporary `SeSecurityPrivilege` adjustment must restore the original token state.

The new SACL array is explicitly non-null, including when it is empty: Microsoft's [SetSecurityDescriptor contract](https://learn.microsoft.com/en-us/windows/win32/wmisdk/setsecuritydescriptor-method-in-class---systemsecurity) says a null SACL leaves the existing SACL unchanged. The same contract specifies how SACL-only requests preserve owner/group/DACL fields. An empty present SACL may be represented differently from the original absent SACL; `HistoricalDescriptorMatches` reports observed equality separately from successful removal. See also the [security descriptor control definitions](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/secrcw32prov/win32-securitydescriptor).

`pending.json` is flushed before the native call. `after.json`, `confirmed.json` and `manifest.json` retain the observed outcome and artifact hashes. A possible write followed by an error or drift is `WriteAttemptedUnverified`, never a claim that nothing changed. Replaying a completed old plan is refused. Preserve partial evidence and investigate the current native descriptor before taking further action.

## Limits and native validation

Version 1 configuration journals record the historical computer name, not a durable namespace identifier, operator authentication or implementation fingerprint. Current source hashes cannot retroactively prove those missing historical facts. The original records must be trusted: a matching hash does not authenticate their author. Windows WMI provides no atomic compare-and-swap for the full security descriptor; an identical namespace recreation or competing ACL writer cannot be excluded. Quiesce competing namespace ACL writers. This command neither restores a whole historical descriptor nor owns descendant ACEs.

The disposable Windows workflow exercises Server 2022/2025 and Windows PowerShell 5.1/PowerShell 7. It creates fresh owned namespaces, redirects only the canonical namespace entry in an owned copied checkout, and runs the actual public Configure/Plan/Recover commands. It verifies sole-ACE and unrelated-ACE recovery, missing-consent refusal, replay refusal, source/artifact hashes and independent cleanup. The production CLI has no arbitrary namespace or fixture bypass. The original root/default namespaces, root namespace inventory, service settings, audit masks, precedence and full parent token are checked independently. Exact current-head native results are recorded in the PR; portable tests alone do not establish Windows behavior.

Windows 11, domain-controller/AD CS deployments, descendant changes, cross-host recovery, event generation, forwarding and Sigma readiness are separate acceptance work. Recovery always grants zero rule-readiness credit.
