# Reviewed registry SACL recovery

`registry-sacl-recovery` removes one explicit registry-root audit ACE proven to have been appended by one completed public `targeted-sacl` operation. The original operation must have selected exactly one built-in registry target with `-TargetSaclIncludeChildren`, and every historical and current descendant inventory must be complete and empty. A populated tree, a pending-only operation, an already-present ACE or an arbitrary registry path is outside this command's scope.

## Review the original evidence

Keep these four distinct files from the original operation:

| Input | Required evidence |
| --- | --- |
| Original selected plan | One `ChangeRequired` registry row, its original descriptor and complete empty descendant snapshot. |
| `<target-id>.pending.json` | Original descriptor and intended addition, recorded before the original write. |
| `<target-id>.confirmed.json` | The same operation's verified after-state and empty descendant observations. |
| Final original result | A successful, non-dry-run result with exactly one matching `Applied` row and complete verification. |

Keep the named Pending and Confirmed files inside the original result's recorded backup directory. The command checks their names and locations, timestamps, schemas, native descriptor bytes, source fingerprints, host context and exact correspondence with the plan and final result. Each input is limited to 4 MiB. Missing, edited, mismatched, incomplete or unsupported records are refused.

The target, principal, mask and inheritance flags are rebuilt from the current bundled catalog and original selection. The descriptors must prove exactly one ordinary explicit audit ACE was appended, with the original ACE order and unrelated descriptor components preserved. A matching ACE that already existed does not establish removal authority.

```powershell
./WELA.ps1 registry-sacl-recovery `
  -RegistryRecoveryOriginalPlanPath C:\WELA\original-plan.json `
  -RegistryRecoveryPendingPath C:\WELA\original-backup\sacl-REPLACE_WITH_TARGET_ID.pending.json `
  -RegistryRecoveryConfirmedPath C:\WELA\original-backup\sacl-REPLACE_WITH_TARGET_ID.confirmed.json `
  -RegistryRecoveryOriginalResultsPath C:\WELA\original-results.json `
  -RegistryRecoveryOutputPath C:\WELA\registry-recovery-review
```

Replace both receipt filenames with the actual matching target ID; do not rename the original files. `Plan` is the default action. It observes the key and creates protected `plan.json` and `manifest.json` files in a new ordinary local output directory. It makes no registry configuration change. Inspect the complete plan, including the exact binary ACE to remove, the original evidence paths and hashes, and current context. Independently retain the reviewed `PlanHash` from the manifest.

Original version-1 records do not authenticate historical operator identity. **Hashes check consistency with trusted records; they do not authenticate their author.** Supply original evidence whose provenance you trust. The current native registry path and last-write metadata also cannot prove durable historical key identity: they do not establish that a key was never deleted and recreated.

## Explicit removal

```powershell
./WELA.ps1 registry-sacl-recovery -RegistryRecoveryAction Restore `
  -RegistryRecoveryPlanPath C:\WELA\registry-recovery-review\plan.json `
  -RegistryRecoveryPlanHash REVIEWED_LOWERCASE_SHA256 `
  -RegistryRecoveryOutputPath C:\WELA\registry-recovery-run `
  -RegistryRecoveryAllowAuditReduction `
  -RegistryRecoveryAllowInheritance
```

Both consent switches are required. Removing the selected ACE reduces auditing. Windows inheritance processing can affect concurrently created children even when the recorded and freshly observed child inventories are empty. Consent does not authorize descendant ACE removal or a populated-tree rollback. `Restore` accepts the reviewed plan/hash and a new output directory; it obtains the original four paths from that plan. `-Auto`, `-DryRun`, `-WhatIf`, arbitrary target overrides and unrelated options are rejected. Use `Plan` for the preview.

Run elevated in native 64-bit Windows with the observation services already running. The plan binds the actual host, supported role/build context, full primary-token/logon observations, source files, all 59 audit masks and typed audit-precedence state. The command rebuilds the plan from the original files and checks the supplied lowercase SHA256 before writing. Changes to the implementation or bound context require renewed assessment; editing a fingerprint does not make old evidence eligible.

The current full descriptor and registry path/last-write identity must exactly match the original completed after-state. Even a benign value edit that changes the key's last-write time causes refusal. Missing keys, links, new children, changed ACEs and unreadable or incomplete observations also refuse recovery. There is no timestamp relaxation or option to overwrite newer changes.

A flushed `pending.json` records removal intent before the one native SACL-only write. Fresh checks on the opened key precede removal of the uniquely proven ACE. Readback verifies all remaining ACE bytes, counts and order, owner, group, DACL, resource-manager control and preserved control flags. The command changes no registry values, audit policy or service configuration, and restores the temporary privilege state. Final checks revalidate the empty child state, native after-state, current context, original inputs, reviewed plan and retained artifact hashes.

## Interpret the result

| Status | Meaning |
| --- | --- |
| `ReviewRequired` | A plan and review hash were retained; no native write occurred. |
| `Refused` | The evidence, consent or current state did not authorize removal. |
| `AddedAceRemoved` | The proven ACE was removed and preservation/readback checks succeeded. |
| `WriteAttemptedUnverified` | A write or cleanup outcome is uncertain; inspect retained observations and receipts before manual action. |

Successful recovery retains `reviewed-plan.json`, `pending.json`, `after.json`, `confirmed.json` and `manifest.json`. The manifest records actual `WriteAttempted`, observed `Before`/`After`, diagnostics and artifact hashes. An unsuccessful run may contain only some of these files. A pending receipt proves intent, not successful removal; process termination, power loss or storage failure can leave no final manifest. There is no automatic rollback or continuation. Replaying a successful recovery plan is refused because its expected pre-state no longer exists.

**`AddedAceRemoved` does not promise the exact historical descriptor bytes.** A formerly absent or null SACL may remain present and empty or null after the ACE is removed. `OriginalDescriptorBytesMatch` separately reports byte-for-byte equality with the descriptor before the original addition. Preserving the other current descriptor components takes precedence over replacing the full descriptor to reproduce that historical representation.

The checks do not atomically lock the registry tree against another writer. Use an isolated change window and investigate partial outcomes manually; matching inherited ACEs do not establish ownership. Recovery grants no event-generation, forwarding or Sigma readiness credit.

## Native validation boundary

The gated disposable Windows suite exercises the public original Plan/Configure and recovery Plan/Restore on an owned mounted hive under Server 2022/2025 and Windows PowerShell 5.1/PowerShell 7. It checks missing consent, stale-plan refusal, actual value-edit and child-creation refusal, unrelated ACE/value preservation, retained evidence and fixture cleanup. The fixture alone prepares audit policy and loads/unloads its owned hive, then verifies the original hive inventory, token, all audit masks and typed precedence. Those fixture operations are absent from the product command. Production identities, populated trees, policy refresh, event generation and backend Sigma evaluation require separate validation.

See [selected SACL configuration](selected-sacl-configuration.md) for original evidence creation and [native registry SACL validation](native-registry-sacl-validation.md) for the separate original-configuration and event-evidence boundary.

Primary API references: Microsoft [SetSecurityInfo and propagation](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo), [RegOpenKeyExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexw), and [RegQueryInfoKeyW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeyw).
