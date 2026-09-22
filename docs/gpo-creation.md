# Create a disabled, unlinked audit GPO

`gpo-create` validates a genuine, narrowly scoped GPMC backup against a current WELA `gpo-package`, then optionally creates one **new GPO with both policy sides disabled and no links**. It never overwrites an existing GPO, activates policy, links an OU/domain/site, changes delegation/filtering, refreshes clients, or deletes a failed candidate. Scope is built-in Windows advanced system audit policy plus DWORD `SCENoApplyLegacyAuditPolicy=1`; Sysmon and other WELA controls are excluded.

This command requires Windows PowerShell 5.1 or PowerShell 7 on Windows, installed GPMC/GroupPolicy management tools, an authenticated account authorized to create GPOs, and a host joined to the explicitly selected domain. Production code installs no tools. Only **single-domain forests** are supported: domain/OU and forest-site links can then be checked through one explicitly pinned writable DC. Workgroup hosts, RODCs, aliases, IP literals, mismatched domain GUIDs, unknown permissions and multi-domain forests are refused.

## Prepare genuine inputs

1. Use `gpo-package` to export and review the intended built-in source profile, role/build, omissions and exact masks. A package is not itself importable. One-sided minimum masks require explicit `PromoteToBoth`; unvalidated zero-mask deployment remains blocked.
2. Follow [source preparation](gpo-package-deployment.md) on an isolated authorized domain. Create an unlinked source GPO and configure **only** the selected advanced audit GUIDs/masks and audit precedence. Leave all User settings empty. Do not add scripts, registry policy files, rights, security options, WMI filters or other extensions.
3. Disable **both Computer and User settings on that source GPO before making its genuine Backup-GPO/GPMC backup**. Do not patch `Backup.xml`, strip unwanted files or fabricate a backup from WELA components. The source backup must already declare both sides disabled; import does not provide an assumption that enabled flags are preserved.
4. Retain the complete genuine backup directory, backup-instance ID (distinct from the original GPO GUID), and WELA package on ordinary local fixed-drive paths. No UNC/device/stream/reparse input paths are accepted. Keep the inputs protected against concurrent editing.

The validator checks cached and native GPMC reports, actual `audit.csv` GUID/mask rows, the typed security template, backup core registrations, metadata and filesystem copy directives, and every selected-backup file/directory. Only the two audit/precedence payloads plus native metadata and known empty directories are supported. The exact absent legacy-ADM wildcard placeholder retained by genuine GPMC backups is allowed only without a Location/callback or any ADM files; Registry.pol and registry policy registration remain refused. Localized display labels do not control policy comparisons. Unknown data is refused rather than silently filtered. Broader SCT/LGPO backups normally fail this narrow validation; a genuine source GPO must be prepared separately.

## Review, plan and create

Save an explicit config, for example `C:\Review\gpo-create.json`:

```json
{
  "SchemaVersion": 1,
  "PackagePath": "C:\\Review\\audit-components",
  "BackupRoot": "C:\\Review\\genuine-gpo-backups",
  "BackupId": "11111111-1111-1111-1111-111111111111",
  "Domain": "lab.example.test",
  "DomainGuid": "22222222-2222-2222-2222-222222222222",
  "Dc": "dc01.lab.example.test",
  "Name": "WELA Audit - reviewed candidate",
  "ReviewedSha256": ""
}
```

Use actual reviewed IDs. `DomainGuid` is the directory domain object's `objectGUID`, not its SID or a source backup ID. Paths may be absolute or relative to this config. Fields are strictly checked; unknown/duplicate JSON properties are rejected. `Name` must be a new plain 2–128 character name and cannot be a default policy name.

```powershell
# Native backup/package review only; no domain connection or output writes.
.\WELA.ps1 gpo-create -GpoCreateConfigPath C:\Review\gpo-create.json
```

Review the returned profile and source/backup identity. Copy the resulting lowercase `ReviewedSha256` into that config. The fingerprint includes every selected backup file, directory, current WELA package file and existing native backup-root manifest. It is an integrity/review binding, not proof of a trusted publisher or valid AD deployment.

```powershell
# Adds actual domain/DC identity and unique-name checks; remains read-only.
.\WELA.ps1 gpo-create -GpoCreateAction Plan -GpoCreateConfigPath C:\Review\gpo-create.json

# No output or GPO creation; still performs real prerequisite reads.
.\WELA.ps1 gpo-create -GpoCreateAction Create -GpoCreateConfigPath C:\Review\gpo-create.json `
  -BackupPath C:\Review\candidate-receipts -DryRun

# Prompts before creating the new candidate. -Auto supplies unattended consent.
.\WELA.ps1 gpo-create -GpoCreateAction Create -GpoCreateConfigPath C:\Review\gpo-create.json `
  -BackupPath C:\Review\candidate-receipts
```

`BackupPath` must be a fresh directory with an existing local parent. The directory receives an owner/SYSTEM/Administrators ACL. WELA writes a reviewed plan and creation-intent receipt, holds reviewed input files against write/delete, and copies the genuine backup **unchanged** into this protected directory. It revalidates those copied bytes; no fake native metadata is generated. The protected copy is the native import source.

The shared configuration runner provides dry-run, consent, before-state journal and final verification. WELA calls `New-GPO` without a starter GPO and records the returned GUID immediately using a new, flushed receipt. It then checks that the exact new object is empty and unlinked, disables both sides, captures a full blank-target receipt, and freshly repeats identity/content/link/permission/version checks before native GPMC import. Both the COM operation and its `GPMResult.OverallStatus()` must succeed. Import targets only the returned GUID and uses no migration table. The readback compares native report and actual pinned-DC SYSVOL payloads, disabled flags, domain/site links, owner/group/DACL report, object identity, and coherent AD/SYSVOL versions. Final readback must still match.

Native creation initially returns an **empty, unlinked** GPO; disabling happens immediately after its durable identity receipt and empty-object checks. If that receipt cannot be persisted, import and further changes are refused. The precreation marker/name receipt and returned GUID identify this empty residual object. WELA never claims a failed run left a verified disabled candidate.

## Evidence and recovery

A successful result is `DisabledUnlinkedCandidateVerified` on the pinned DC at that time. `DeploymentVerified` remains false and Sigma EVTX credit remains zero. The package's declared role/build is not a generated WMI/security filter and does not constrain future linking. Security filtering/delegation stays at the new GPO's native defaults; review it separately before any later enabling or linking.

Retain `reviewed-plan.json`, `creation-intent.json`, `created-gpo.json`, `blank-target.json`, `import-intent.json`, `before.jsonl`, `result.json`, and the copied genuine backup. Failure stops the workflow and preserves available receipts; it does not retry into an existing GPO or automatically delete/restore anything. If native creation succeeded but returned no identity or saving the receipt failed, search the exact selected DC/name and unique comment marker from `creation-intent.json`. Inspect the object and all current links before any separately authorized cleanup. Existing evidence paths are never reused.

These checks are **not a transaction or compare-and-swap lock across AD and SYSVOL**. Another authorized administrator can race between creation, name/flags/link checks, native import and readback. A fresh/final mismatch is a failed candidate, not automatic rollback authority. Coordinated change control and subsequent replication checks remain necessary. Readback establishes neither replication to other DCs nor client policy processing, precedence after refresh, persistence, event generation, forwarding or detection success.

## Validation boundary

Safe fixtures exercise the public orchestration with native domain adapters mocked: source/payload drift, unrelated policies, duplicate names, domain changes, blank-target changes, receipt failures, import failures, permissions/content/link mismatches, final drift, dry-run and decline. Public CLI tests check option dispatch and negative exit behavior.

Windows Server 2022/2025 CI exercises real GPMC backup/report/OverallStatus using Microsoft's unchanged **Windows Server 2022 Security Baseline** archive from the [Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319), pinned to SHA-256 `49590cc694626d171fc934fafea6494f13ecd3843086704b7a5b98355909b8e0`. Its broad policy is deliberately refused. Actual workgroup-host refusal and unchanged native local audit/precedence state are checked in PowerShell 5.1 and 7. The test can explicitly install GPMC only on disposable GitHub-hosted runners; it creates no domain and performs no domain policy writes.

**Positive creation/import from a genuine narrow backup into AD/SYSVOL remains pending isolated-domain acceptance.** Required follow-up: collect the real source backup and typed native results, confirm both sides disabled and no domain/OU/site links before/after import, review permissions and versions, test failure/recovery with concurrent administrators, then separately stage representative Windows 11, member server, DC and AD CS client-policy/event/arrival checks. Hosted workgroup evidence is not a substitute for these steps. Issue #2 remains related work until acceptance is complete.

## Microsoft sources

- [New-GPO: creates an unlinked GPO and rejects duplicate names](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/new-gpo?view=windowsserver2025-ps)
- [Native backup handling and archive preservation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-backup-restore)
- [GPMC GetDomain: explicit DC with flags 0](https://learn.microsoft.com/en-us/windows/win32/api/gpmgmt/nf-gpmgmt-igpm-getdomain)
- [GPMBackup report generation](https://learn.microsoft.com/en-us/windows/win32/api/gpmgmt/nf-gpmgmt-igpmbackup-generatereport)
- [Native GPO import: settings replacement and destination ACL/link preservation](https://learn.microsoft.com/en-us/windows/win32/api/gpmgmt/nf-gpmgmt-igpmgpo-import)
- [OverallStatus must be checked as well as the native operation](https://learn.microsoft.com/en-us/windows/win32/api/gpmgmt/nf-gpmgmt-igpmresult-overallstatus)
+### Issue 2 coverage

GPO creation is an explicit export workflow with role/build/profile provenance and unsupported-control disclosures. Export success does not claim domain linking, delegation, replication, client refresh, or resultant-policy application.
