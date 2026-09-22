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

An Audit without target IDs returns the catalog and user inventory. Audit/Plan with IDs reads selected target descriptors and, when child consent applies to a container, the bounded descendant inventory described below. Plan requires nonempty selection; Configure requires the saved plan and matching IDs. A changed catalog, generator, source profile, target identity/security descriptor, or actual host context requires a fresh review. Plan files use bounded strict JSON and trusted definitions are regenerated; editing a path, principal, mask or source identity cannot supply arbitrary native write instructions. This initial command uses built-in profiles, not `-ProfileFile` or external target catalogs.

## Exact policy and target boundaries

WELA companion targets retain Everyone, Success+Failure and their declared rights. Microsoft WEF Appendix B Run/RunOnce entries retain Authenticated Users, Success and their distinct SetValue/CreateSubKey/Delete masks. They have distinct target IDs and are never silently merged into one recommendation. Inclusion in the companion catalog does not mean every Microsoft/CIS/ASD profile requires every WELA path. See [the shared companion plan](targeted-sacl-planning.md) for source distinctions.

The required File System or Registry success/failure audit bits and typed `SCENoApplyLegacyAuditPolicy=1` must **already** be observed. Unselected optional or not-applicable policies and explicit No Auditing block configuration. An unchanged/Not Configured source can use separately established effective auditing, but this workflow does not enable it. Configure an appropriate policy separately through its authority and generate a fresh plan afterward. Handle Manipulation events and other prerequisites are separate; this command does not infer that all event families will fire.

Unloaded hives, missing files/keys, remote or mapped-network paths, reparse points, unknown user folders and unresolved catalog entries remain blocked. No offline hive is mounted, and no sensitive file or autostart key is created. Loaded-user paths use that user's known-folder metadata; another user's AppData is never replaced with the operator's environment. Directory and registry inheritance requires explicit `-TargetSaclIncludeChildren`: Windows can propagate inheritable SACL ACEs to **existing** descendants. The reviewed plan must now include a complete bounded descendant capture; an incomplete capture blocks configuration. Protection barriers are preserved and reported separately from inherited-ACE observations.

## Native preservation, receipts and recovery

Native reads and writes use a handle to the selected object. File handles verify the final local path and file identity; registry components are opened without following symbolic links. Registry identity includes the observed last-write time, so unrelated edits can conservatively require a new plan. The writer rereads the handle immediately before `SetSecurityInfo` with **SACL_SECURITY_INFORMATION only**, passing no owner, group or DACL changes. The original SACL entries are retained as binary ACEs and the requested ordinary audit ACE is appended. Unknown or inherited entries are preserved without treating them as proof of the requested explicit ACE. An existing explicit ordinary ACE with matching flags/SID and all required rights is already compliant.

Each attempted change first creates `<target-id>.pending.json`, containing the original descriptor bytes for the recorded observation scope, ACEs, target identity, source hashes, proposed audit entry and every reviewed descendant snapshot. Only successful native write, selected-root preservation/readback and all required descendant outcomes create the separate `<target-id>.confirmed.json`. A failed write, unreadable after-state or privilege-restoration failure leaves pending evidence and returns failure, without a confirmed ownership claim. Final checks detect changes after an earlier successful write. Partial failures stay visible; an applied earlier target is not silently rolled back. A confirmed receipt records its verified moment and must still be compared with the final result and current state.

For recovery, review the receipts and a fresh descriptor first. Remove only the explicit ACE demonstrated to have been added by this run; do not remove a matching ACE that was already present. Preserve the existing owner, group, DACL, protection flags and all newer audit entries. If Windows propagated inheritance, use the child snapshots and observations for manual assessment; a matching inherited ACE does not establish that this run owns it. No automatic full-descriptor replacement or bulk rollback is provided by this command. Pending receipts cannot establish that an ACE belongs to WELA; retain them for manual investigation.

For one completed registry-root addition with complete empty historical and current descendant observations, the separate [registry SACL recovery command](registry-sacl-recovery.md) checks the original plan, named Pending/Confirmed receipts and final successful result. A reviewed recovery hash and both audit-reduction/inheritance consents authorize removal of only the proven explicit ACE. Populated trees, pending-only records and full-descriptor rollback remain outside that command's scope.

Windows security updates are not a compare-and-swap transaction against other administrators or GPO. Fresh-state checks and handle-bound mutation reduce races but do not lock out concurrent SACL writers. Use an isolated change window; no later policy persistence or race-free inheritance guarantee is claimed.

## Reviewed descendant evidence

`-TargetSaclIncludeChildren` remains explicit consent for the native setter's inheritance effects. For each selected container it now requires two matching scans of at most **128 existing descendants**, at most **16 levels** deep, with at most **2 MiB** of serialized child snapshots. All selected roots must also fit the existing 4 MiB plan limit. Each scan has a 30-second check between native operations; individual Windows reads are not cancellable, so this is not a hard native-call timeout. These bounds cannot be overridden by `-Auto`. Select a smaller supported catalog scope or assess the tree separately when the capture cannot be completed; arbitrary paths and alternative hives cannot be supplied.

The plan records each child's exact path, immediate parent, depth, native identity/descriptor, and SACL protection barrier. It includes children below a protected container so their preservation can be checked; it does not clear protection. Native registry enumeration requests only the additional enumerate right on the current container, uses the 64-bit view and rejects symbolic-link components before reading the target descriptor. File enumeration rejects reparse components, ambiguous names and repeated file identities such as hard-link aliases. Missing, denied, capped, linked, unstable or oversized captures stay `Incomplete` and block the entire preflight. Parent-only file operations retain their existing behavior.

Configure regenerates the descendants and compares them to the reviewed plan, repeats the capture before writing the pending backup, and again after that backup immediately before the selected-root write. Overlapping selected ancestors/descendants are refused before any change. Descendants are **never** passed to the writer: Windows performs propagation from the one selected-root SACL update. After any attempted native write, a separate `*.descendants-observed.json` records the bounded child readback when available. A failed or unreadable after-state leaves Pending evidence and no Confirmed receipt. A final scan compares membership, identities and descriptors again; later drift fails the run even if a Confirmed receipt records an earlier verified moment.

Per-child outcomes are distinct:

- `InheritedAceObserved`: the required ordinary inherited audit ACE was seen, with all original binary ACEs, owner, group, DACL and non-SACL/protection flags preserved. Only SACL-present and SACL automatic-inheritance bookkeeping flags may change.
- `ProtectedUnchanged`: the child's full descriptor is unchanged under its own or an ancestor's SACL protection barrier; this is not inherited auditing coverage.
- `PreservedWithoutRequestedInheritance`: original state is preserved but the selected new ACE is parent-only; existing inheritable entries can still have triggered the scan.
- `NewUnreviewedChild` or `Unverified`: a child appeared, disappeared, changed identity, could not be read, lost an original ACE, gained an unexplained explicit/unknown ACE, or lacks its expected inherited audit ACE. The run fails rather than reporting full propagation.

An already compliant root is not rewritten to repair child inheritance. If its expected descendant ACEs are missing, WELA blocks the plan and requires separate assessment. A fresh compliant root/descendant plan remains idempotent.

This is observational verification, **not an atomic tree transaction**. Concurrent creation/deletion/ACL changes can happen between scans or during Windows propagation; newly created children may inherit despite having no pre-write backup. A post-write failure cannot undo such effects safely. File identity uses the native volume/file index/creation tuple; registry identity uses the path and last-write metadata, which can change during a SACL update and cannot prove that a key was not deleted and recreated during that interval. Registry post-write verification therefore reports path/descriptor preservation without claiming durable object identity. No receipt establishes child-ACE ownership or authorizes automatic/bulk rollback. Preserve Pending evidence and investigate against fresh state; do not restore full child descriptors or remove every matching inherited ACE.

The Windows disposable fixture now uses populated file and registry trees, verifies actual native inherited ACEs on the open branch and unchanged protected branches, checks rerun inputs without a second write, and detects a newly appeared child. It snapshots/restores all audit masks and typed precedence, restores privilege state and verifies removal of its owned objects. It does not apply changes to production catalog paths. These tests establish only their observed Server 2022/2025 cases; they provide no general tree, future-child, forwarding or Sigma/backend coverage credit.

## Validation

Mocked tests cover selection, source-specific masks, unsupported consent, source/plan/target races, denied reads, partial writes, non-SACL drift, pending/confirmed receipts, idempotence and public command guards. The Windows workflow explicitly permits mutations only on GitHub-hosted disposable Server 2022/2025 runners: it creates owned temporary file/registry targets, temporarily enables their two audit subcategories and precedence, adds audit ACEs through the real adapter, and searches for benign 4663/4657 events matching the exact targets. It restores all original audit masks and typed precedence and removes only owned targets. This fixture does not modify any catalog system target.

The separate [public registry lifecycle fixture](native-registry-sacl-validation.md) mounts a newly saved, fixture-owned hive under a fresh synthetic user SID. The unchanged public catalog resolves its RunOnce key, then actual CLI Plan/DryRun/Configure calls exercise the reviewed lifecycle and one exact local 4657. Only the fixture loads/unloads hives and prepares auditing; the product behavior above is unchanged. This leaf fixture does not replace populated-tree inheritance validation.

The [public filesystem lifecycle fixture](native-filesystem-sacl-validation.md) resolves a genuine built-in Signal target through an owned synthetic profile and redirected known folder. It exercises actual public selection, Plan/DryRun/Configure, stale-child refusal and idempotence on a populated tree, checks protected descendants, and matches one public leaf-read probe to local4663 XML. Only the disposable fixture registers its profile and mounts its hive.

Native CI results must be reviewed before claiming those test cases passed. Windows 11, DC/CA, other user-redirection/access scenarios, large/changing production trees, forwarding and actual Sigma/backend execution remain separate acceptance work. Every report remains `GenerationReadiness=Conditional` with `UsableRuleCredit=0`.

Primary API references: [GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo), [SetSecurityInfo and inheritance](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo), [registry open/link behavior](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexw), [file handle and sharing flags](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).

Native reads request the explicit Windows SDK section union `0x1ff`: owner, group, DACL, audit, integrity label, resource attributes, central-access policy, process trust label and access filter. Snapshots record `SecurityInformation=511` and `DescriptorScope`; future sections are explicitly unobserved. Server 2022/2025 file-handle diagnostics returned access denied for the aggregate BACKUP flag but success for this complete current section union. The adapter does not acquire broader privileges or drop unreadable sections; a failed union read blocks the target. Writes still request only `SACL_SECURITY_INFORMATION`. Existing inheritable ACEs, including unknown ACE types, also require child consent on containers because the native setter can propagate them. Two source entries that resolve to the same physical target are blocked before any write: configure one, then review a fresh plan for the other. See Microsoft’s [security information flags](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-information).

Section constants are defined by Microsoft’s [Windows SDK winnt.h](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/winnt.h). Future descriptor sections require a reviewed update to this bounded reader before they can be verified.
