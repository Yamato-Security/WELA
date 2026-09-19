# Optional WMI namespace auditing

`wmi-auditing` appends reviewed success-audit entries to explicitly selected **local** WMI namespace SACLs. It does not run during ordinary `configure`, change namespace access permissions, create namespaces, enable remote WMI access, change audit policy, install a forwarding subscription, or grant rule-coverage credit. PowerShell 5.1 and PowerShell 7 on Windows use the same `System.Management` provider methods.

```powershell
./WELA.ps1 wmi-auditing -WmiAction List
./WELA.ps1 wmi-auditing -WmiAction Audit -WmiNamespace 'root\cimv2' -ResultsPath wmi-before.json
./WELA.ps1 wmi-auditing -WmiAction Plan -WmiNamespace 'root\cimv2','root\subscription' -ResultsPath wmi-plan.json
./WELA.ps1 wmi-auditing -WmiAction Configure -WmiNamespace 'root\cimv2' -DryRun
./WELA.ps1 wmi-auditing -WmiAction Configure -WmiNamespace 'root\cimv2' -BackupPath C:\WelaBackups\wmi-change-001 -ResultsPath wmi-result.json
# Explicitly opt in to the reference script's descendant inheritance:
./WELA.ps1 wmi-auditing -WmiAction Configure -WmiNamespace 'root\subscription' -WmiIncludeChildren
```

The default action is read-only `List`. Audit/Plan/Configure require exact namespace selections; wildcards, remote paths, unreviewed namespaces and empty selections are rejected. `-Auto` skips per-namespace confirmation after the operator has selected the scope. `-DryRun` is supported only with Configure, and calls no setter or journal writer. `-Profile` and `-Baseline` do not select WMI SACLs.

## Reference entries and scope

The entries come from the [ASD WMI script pinned at 59041b5](https://github.com/AustralianCyberSecurityCentre/windows_event_logging/blob/59041b5d4586789a751171fb752be1624ad5e3b4/events/wmi_auditing/wmi_auditing.ps1). Every new ACE has type 2 (system audit), success only. Existing failure entries and unfamiliar ACEs are retained.

| Namespace | Principal | Mask | Audited namespace rights | ASD flags |
| --- | --- | --- | --- | --- |
| `root\cimv2` | Everyone `S-1-1-0` | `0x40002` (262146) | Execute Methods, Edit Security | 64 |
| `root\cimv2` | Interactive `S-1-5-4` | `0x1` | Enable Account / read | 64 |
| `root\cimv2` | Network `S-1-5-2` | `0x1` | Enable Account / read | 64 |
| `root\cimv2` | Batch `S-1-5-3` | `0x1` | Enable Account / read | 64 |
| `root\SecurityCenter` | Everyone | `0x40001` (262145) | Enable Account / read, Edit Security | 66 |
| `root\SecurityCenter2` | Everyone | `0x40001` (262145) | Enable Account / read, Edit Security | 66 |
| `root\subscription` | Everyone | `0x4001E` (262174) | Execute Methods, Full Write, Partial Write, Provider Write, Edit Security | 66 |
| `root\default` | Everyone | `0x4001F` (262175) | Read plus all preceding rights | 66 |

The numeric subscription mask includes Execute Methods even though the reference script's comment omits it. WELA uses the actual numeric mask. Flags 64 mean success on this namespace; 66 add container inheritance. **By default WELA uses 64 for every selection**, limiting new entries to that namespace. `-WmiIncludeChildren` enables the reference's flag 66 for the four applicable namespaces. This may propagate audit ACEs to inheriting descendants, including existing and future child namespaces; it does not grant access. Child ACL propagation is not enumerated, backed up or verified by this command, and is an explicit additional scope requiring a lab review. Existing inherited entries are retained in either mode. SecurityCenter namespaces are commonly absent on servers; absence is reported rather than treated as successful configuration.

## Privileges, preservation and results

Run elevated with **SeSecurityPrivilege assigned** for Audit/Plan/Configure. WELA enables this privilege in its process while accessing the descriptor, restores the previous token state afterward, and requests privileges for the local WMI connection. Without it a provider can return a DACL while omitting the SACL; WELA refuses that ambiguous read. List only enumerates the supported root child namespaces and reports Present, NotInstalled or Unknown.

Each GetSecurityDescriptor and SetSecurityDescriptor return code must be explicitly zero. Exceptions, denied/missing namespaces, incomplete descriptors, nonzero return codes, ineffective writes and failed read-back are failures. The journal stores the complete provider descriptor as JSON and MOF strings before the setter is called; nested entries cannot be truncated by the outer result serializer. Native objects are cloned rather than rebuilt from a shortened permission list. The native setter request clears `SE_DACL_PRESENT` and leaves DACL, owner and group null: the [documented provider contract](https://learn.microsoft.com/en-us/windows/win32/wmisdk/setsecuritydescriptor-method-in-class---systemsecurity) preserves those access fields rather than rewriting them. `SE_SACL_PRESENT` requests the SACL update. Full read-back still verifies DACL order, owner, group, other control flags and every original audit entry against the complete recovery snapshot. Unknown entries are never deliberately simplified or discarded.

Privilege restoration runs even if connection disposal fails. Both enabling and restoring the token privilege check the API return value and last-error code; [AdjustTokenPrivileges](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges) can return success while reporting an unassigned privilege. A restoration error is reported as a failed operation, not silently treated as restored state.

Immediately before writing, WELA reads the full descriptor again and refuses to overwrite a changed snapshot. Read-back checks all original fields/ACE multiplicities and every requested exact audit entry. The final check detects descriptor drift after verification. This is not an atomic transaction with other administrators or management software: changes between the last read and the provider write remain possible. No automatic rollback overwrites concurrent changes.

An exact existing entry is not duplicated. Different masks, audit outcomes, inheritance, object-specific ACEs or inherited ACEs are preserved and do not suppress the explicit requested entry. Result statuses use the shared configuration contract: Applied/AlreadyCompliant indicate observed SACL compliance, Skipped includes dry-run or declined changes, and Failed/Overridden produce exit code 1. Exit code 0 alone is not evidence of a write or successful event generation.

## Audit prerequisites and local/remote evidence

WELA separately observes the effective **Other Object Access Events** audit policy (success bit) without changing it. A missing/unknown prerequisite is visible in `Prerequisite`; a successful SACL update alone does not establish event readiness. Review audit precedence and the effective policy using the separate audit-policy workflow.

[Microsoft documents namespace auditing](https://learn.microsoft.com/en-us/windows/win32/wmisdk/access-to-wmi-namespaces) as Security event **4662** for matching namespace access checks. It does not establish whether the subsequent provider operation succeeded. Interactive/Network/Batch SIDs select token membership, not a universal local/remote classification: validate the logon type, user SID, namespace and access mask in observed XML. Remote Enable (`0x20`) is not added to the DACL or the new audit mask. WMI-Activity/Operational telemetry is a separate evidence source and is not made equivalent to namespace Security events.

## Recovery and remaining lab verification

Keep the new backup directory and result JSON outside temporary folders. `before.jsonl` contains each selected namespace's original `DescriptorJson` and `DescriptorMof`, namespace name and proposed entries. Compare these with a fresh Audit export before making any recovery change. In an elevated WMI Control (`wmimgmt.msc`), select the exact namespace, Security > Advanced > Auditing, and remove only entries that this run added after confirming they were absent from the original descriptor. Restore changed audit flags/masks from the original export if necessary; retain unrelated owner/group/DACL and newer administrative changes. WELA deliberately provides no blind whole-descriptor restore. An existing matching ACE was not created by this run and must not be removed. If descendant inheritance was enabled, inspect affected child namespaces independently and use a pre-change machine snapshot if a complete rollback is needed.

CI uses synthetic descriptors, a real privileged read of root\cimv2, an in-memory native writer adapter and a read-only dry-run on Windows PowerShell 5.1/7. A separate integration job performs real SACL writes only on uniquely created temporary namespaces on disposable Server 2022/2025 runners, verifies read-back/idempotence and deletes its own namespaces. It never changes the SACL of an existing namespace. **Writes to the five production target namespaces, Windows 11 behavior, benign local/remote event generation, child propagation and forwarding have not been verified by these tests.** Before deployment, use isolated patched snapshots of Windows 11, member server, domain controller and AD CS hosts; record descriptors/effective audit policy before and after, repeat configuration for idempotence, issue benign local and remote calls with known tokens, capture Security 4662 XML, and test the chosen WEF subscription and collector receipt. Validate namespace `ObjectName` and access masks, not EventID alone. These are pending acceptance labs, not claimed Sigma uplift.

Additional primary references: [SetSecurityDescriptor and preservation flags](https://learn.microsoft.com/en-us/windows/win32/wmisdk/setsecuritydescriptor-method-in-class---systemsecurity), [namespace access masks](https://learn.microsoft.com/en-us/windows/win32/wmisdk/namespace-access-rights-constants), [namespace inheritance flags](https://learn.microsoft.com/en-us/windows/win32/wmisdk/namespace-ace-flag-constants).

## Native control-flag readback evidence

The disposable-namespace test addresses [review comment 4052822447](https://github.com/Yamato-Security/WELA/pull/399#discussion_r4052822447) without weakening preservation checks. [The verified CI run](https://github.com/Yamato-Security/WELA/actions/runs/35436825928) used the real production SACL writer and configuration runner against eight fresh namespaces (two ACE flag modes, two PowerShell versions and two operating systems). Each started without a SACL, retained owner/group/DACL, passed first-write readback and an idempotent repeat, then was deleted. Full descriptor snapshots and cleanup results are in the job logs.

| Host build | PowerShell | ACE flags tested | ControlFlags before | ControlFlags after |
| --- | --- | --- | --- | --- |
| Server 2022 / 20348 | 5.1.20348.5622, 7.6.6 | 64 and 66 | 32772 / `0x8004` | 32788 / `0x8014` |
| Server 2025 / 26100 | 5.1.26100.33296, 7.6.5 | 64 and 66 | 32772 / `0x8004` | 32788 / `0x8014` |

No extra auto-inherited/defaulted bit appeared in these cases. The existing `Before.ControlFlags | 0x10` equality is retained: an unexpected flag change still fails preservation verification. These results establish this provider behavior for the listed clean namespace scenarios, not every existing namespace or Windows version.

To repeat on a **disposable Windows lab VM** (this is a mutating integration test):

```powershell
./tests/WmiNamespaceAuditing.DisposableNamespace.Tests.ps1 -AllowDisposableNamespaceWrite -EvidencePath wmi-native.json
```

The script accepts no target namespace. It uses generated `root\WelaSaclTest_<GUID>` names, creates them with CreateOnly, verifies the returned identity, runs the writer only there, and removes only instances it created. The normal read-only test remains separate. It does not enable audit policy, generate controlled Security 4662 evidence or test forwarding. Namespace lifecycle follows Microsoft's [__Namespace contract](https://learn.microsoft.com/en-us/windows/win32/wmisdk/--namespace); SACL-only updates follow the [SetSecurityDescriptor contract](https://learn.microsoft.com/en-us/windows/win32/wmisdk/setsecuritydescriptor-method-in-class---systemsecurity).

The separate [local WMI probe](wmi-probe.md) can collect bounded namespace-read Security4662 evidence using existing prerequisites. It makes no production namespace/policy changes; its owned-namespace native fixture covers a separate local read case, not remote access or forwarding.
