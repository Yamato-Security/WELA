# Selected local file and registry audit SACLs

`targeted-sacl` is a dedicated, opt-in workflow for existing local objects from a built-in profile's shared targeted-SACL companion plan. Its default action is read-only `Audit`. It adds only a selected audit ACE; it never enables object-audit policy, creates missing targets, loads user hives, changes DACLs/owners, clears logs or configures global object auditing. Sysmon is excluded. The existing broader `configure-sacl` command remains separate.

## Discover, review, then configure

Use native 64-bit Windows PowerShell 5.1 or PowerShell 7. Reading selected SACLs requires an assigned `SeSecurityPrivilege`; an elevated administrator normally has it. The command enables that privilege only around a native target operation and restores its previous state on success or failure. Impersonated callers are refused. Unknown privileges, descriptor reads or role/build/patch context block configuration.

```powershell
# Inventory resolves the shared definitions and loaded-user known folders,
# but does not read any object SACL until an explicit target ID is selected.
$inventory = ./WELA.ps1 targeted-sacl -TargetSaclProfile wela-2.2.0 -IncludeOptional
$inventory.Catalog | Select-Object Id, @{n='Path';e={$_.Definition.Path}},
  @{n='Origin';e={$_.Definition.Origin}}, @{n='Principal';e={$_.Definition.PrincipalSid}}

# Select exactly one reviewed WELA Run target, distinct from the WEF entry.
$target = @($inventory.Catalog | Where-Object {
  $_.Definition.Path -eq 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -and
  $_.Definition.PrincipalSid -eq 'S-1-1-0'
})
if ($target.Count -ne 1) { throw 'Review an unambiguous target ID.' }
$targetId = $target[0].Id

./WELA.ps1 targeted-sacl -TargetSaclAction Plan -TargetSaclProfile wela-2.2.0 `
  -IncludeOptional -TargetSaclId $targetId -TargetSaclIncludeChildren `
  -ResultsPath .\selected-sacl-plan.json

# Inspect the complete plan, including Status, Diagnostic, Before and Ace.
./WELA.ps1 targeted-sacl -TargetSaclAction Configure `
  -TargetSaclPlanPath .\selected-sacl-plan.json -TargetSaclId $targetId `
  -IncludeOptional -TargetSaclIncludeChildren -DryRun

# Run only after reviewing the actual target and inheritance effects.
./WELA.ps1 targeted-sacl -TargetSaclAction Configure `
  -TargetSaclPlanPath .\selected-sacl-plan.json -TargetSaclId $targetId `
  -IncludeOptional -TargetSaclIncludeChildren -BackupPath C:\WELA-Recovery\selected-001 `
  -ResultsPath .\selected-sacl-results.json
```

The backup parent must already exist; use an operator-controlled recovery location. The final backup directory and result files must be new. Paths resolve relative to PowerShell's current location. `-Auto` accepts per-target confirmation only; it does not bypass selection, source/context, policy, inheritance or descriptor checks. `-DryRun` is supported only for Configure and creates no recovery files or target changes. The same exact target IDs, optional selection and inheritance consent must be supplied when consuming the plan. These dedicated options are rejected on unrelated commands, including legacy `configure-sacl`.

An Audit without target IDs returns the catalog and user inventory. Audit/Plan with IDs reads only selected target descriptors. Plan requires nonempty selection; Configure requires the saved plan and matching IDs. A changed catalog, generator, source profile, target identity/security descriptor, or actual host context requires a fresh review. Plan files use bounded strict JSON and trusted definitions are regenerated; editing a path, principal, mask or source identity cannot supply arbitrary native write instructions. This initial command uses built-in profiles, not `-ProfileFile` or external target catalogs.

## Exact policy and target boundaries

WELA companion targets retain Everyone, Success+Failure and their declared rights. Microsoft WEF Appendix B Run/RunOnce entries retain Authenticated Users, Success and their distinct SetValue/CreateSubKey/Delete masks. They have distinct target IDs and are never silently merged into one recommendation. Inclusion in the companion catalog does not mean every Microsoft/CIS/ASD profile requires every WELA path. See [the shared companion plan](targeted-sacl-planning.md) for source distinctions.

The required File System or Registry success/failure audit bits and typed `SCENoApplyLegacyAuditPolicy=1` must **already** be observed. Unselected optional or not-applicable policies and explicit No Auditing block configuration. An unchanged/Not Configured source can use separately established effective auditing, but this workflow does not enable it. Configure an appropriate policy separately through its authority and generate a fresh plan afterward. Handle Manipulation events and other prerequisites are separate; this command does not infer that all event families will fire.

Unloaded hives, missing files/keys, remote or mapped-network paths, reparse points, unknown user folders and unresolved catalog entries remain blocked. No offline hive is mounted, and no sensitive file or autostart key is created. Loaded-user paths use that user's known-folder metadata; another user's AppData is never replaced with the operator's environment. Directory and registry inheritance requires explicit `-TargetSaclIncludeChildren`: Windows can propagate inheritable SACL ACEs to **existing** descendants. Review those descendants separately; the report verifies the selected object, not complete descendant coverage.

## Native preservation, receipts and recovery

Native reads and writes use a handle to the selected object. File handles verify the final local path and file identity; registry components are opened without following symbolic links. Registry identity includes the observed last-write time, so unrelated edits can conservatively require a new plan. The writer rereads the handle immediately before `SetSecurityInfo` with **SACL_SECURITY_INFORMATION only**, passing no owner, group or DACL changes. The original SACL entries are retained as binary ACEs and the requested ordinary audit ACE is appended. Unknown or inherited entries are preserved without treating them as proof of the requested explicit ACE. An existing explicit ordinary ACE with matching flags/SID and all required rights is already compliant.

Each attempted change first creates `<target-id>.pending.json`, containing the complete original descriptor bytes, ACEs, target identity, source hashes and proposed audit entry. Only successful native write, preserved-state checks and matching readback create the separate `<target-id>.confirmed.json`. A failed write, unreadable after-state or privilege-restoration failure leaves pending evidence and returns failure, without a confirmed ownership claim. Final checks detect changes after an earlier successful write. Partial failures stay visible; an applied earlier target is not silently rolled back. A confirmed receipt records its verified moment and must still be compared with the final result and current state.

For recovery, review the receipts and a fresh descriptor first. Remove only the explicit ACE demonstrated to have been added by this run; do not remove a matching ACE that was already present. Preserve the existing owner, group, DACL, protection flags and all newer audit entries. If Windows propagated inheritance, inspect descendants separately. No automatic full-descriptor replacement or bulk rollback is provided by this command. Pending receipts cannot establish that an ACE belongs to WELA; retain them for manual investigation.

Windows security updates are not a compare-and-swap transaction against other administrators or GPO. Fresh-state checks and handle-bound mutation reduce races but do not lock out concurrent SACL writers. Use an isolated change window; no later policy persistence or race-free inheritance guarantee is claimed.

## Validation

Mocked tests cover selection, source-specific masks, unsupported consent, source/plan/target races, denied reads, partial writes, non-SACL drift, pending/confirmed receipts, idempotence and public command guards. The Windows workflow explicitly permits mutations only on GitHub-hosted disposable Server 2022/2025 runners: it creates owned temporary file/registry targets, temporarily enables their two audit subcategories and precedence, adds audit ACEs through the real adapter, and searches for benign 4663/4657 events matching the exact targets. It restores all original audit masks and typed precedence and removes only owned targets. This fixture does not modify any catalog system target.

Native CI results must be reviewed before claiming those test cases passed. Windows 11, DC/CA, user redirection, inheritance across populated trees, forwarding and actual Sigma/backend execution remain separate acceptance work. Every report remains `GenerationReadiness=Conditional` with `UsableRuleCredit=0`.

Primary API references: [GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo), [SetSecurityInfo and inheritance](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo), [registry open/link behavior](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexw), [file handle and sharing flags](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).

Native reads request `BACKUP_SECURITY_INFORMATION` so recovery evidence includes all descriptor sections, including resource and central-access-policy ACEs. Writes still request only `SACL_SECURITY_INFORMATION`. Existing inheritable ACEs, including unknown ACE types, also require child consent on containers because the native setter can propagate them. Two source entries that resolve to the same physical target are blocked before any write: configure one, then review a fresh plan for the other. See Microsoft’s [security information flags](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-information).
