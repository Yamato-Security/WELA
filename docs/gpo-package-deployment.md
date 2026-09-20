# Preparing and reviewing a genuine audit-policy GPO

This WELA folder contains **deployment components, not a GPO backup**. Do not pass it to `Import-GPO`, copy it into SYSVOL, fabricate `Backup.xml`, or edit a genuine archived backup to insert its files. Microsoft directs administrators to manage archived backups through GPMC. No domain creation, import, linking, filtering, delegation or policy refresh is performed by WELA's package commands. [Microsoft backup/import guidance](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-backup-restore).

## Prepare the source policy in an isolated domain

1. Verify the component package with the same reviewed WELA version. Read `review.md`, including every omitted/expanded row and object/service prerequisites. Confirm the intended target role, build, scope and source version; these are declared package inputs, not observations of a domain's computers.
2. On a disposable, snapshotted lab, use GPMC to create a **new unlinked source GPO**. Leave existing GPOs, default domain policies and links untouched. In the Group Policy Management Editor, enter only the exported rows under Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration. `ExportMask` 1 is Success, 2 is Failure, 3 is Success and Failure. Leave omitted rows Not Configured in this new GPO; do not interpret omission as disabling auditing.
3. In the same GPO, enable Security Options > **Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings**. The companion `GptTmpl.inf` shows the exact DWORD requirement. Do not add legacy category audit policy, audit failure options, privileges, SACLs or unrelated registry settings.
4. Review GPMC's Settings report against the package. Require an exact match for the selected audit GUIDs/masks and precedence=1, with no unexpected Computer or User policy settings. Confirm no links or WMI filter. Review the GPO's security filtering/delegation independently. Back up this source GPO through GPMC or `Backup-GPO` into a fresh protected directory, retaining its **backup-instance ID**, source GPO ID, report and hashes.

This manual source-GPO preparation is the supported path for a narrow, genuine domain backup. Microsoft documents creating an [unlinked GPO](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-management-console) and generating backups through [Backup-GPO](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/backup-gpo?view=windowsserver2025-ps).

## Optional LGPO lab route

Obtain Microsoft's signed LGPO utility and its documentation from the [Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319); WELA does not bundle or execute it. LGPO v3 documents `/s GptTmpl.inf` for a security template, `/a audit.csv` for advanced auditing and `/b directory /n display-name` for a genuine local-policy backup. These **apply modes change the lab host** and are outside the offline package workflow. Snapshot and record the lab's policy first; inspect all generated settings and compare effective policy before/after. Do not run them on a shared or production administrator workstation.

`/a` and `/ac` differ: `/ac` clears existing advanced auditing before application and copies the CSV into local policy. WELA does not provide a clearing command. `/a` must not be presented as proof of persistent GPO configuration: local policy editor state, effective AuditPol state and the audit client-side extension are separate observations. LGPO `/e audit` enables that extension for local processing, but neither its use nor successful import proves correct later policy application.

LGPO `/b` backs up local policy, including security settings, current advanced audit state, registry policy and configured extensions. **Its output can include settings absent from this package**, even on a lab machine. Review the complete backup in GPMC. If it contains extras, edit a newly created isolated source GPO through GPMC and make a new genuine backup; do not remove files or patch XML inside the archive. A generic local-policy backup is not automatically a narrow WELA audit-only backup. Microsoft explains the difference between [AuditPol state and local policy](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/auditpol-local-security-policy-results-differ).

## Reviewed create-new-unlinked procedure

The following is an **operator procedure for an already prepared, genuine, fully reviewed backup**. It is not generated executable content and WELA does not run it. Review its backup by instance ID through GPMC's Manage Backups/Settings report (or the native `GPMBackupDir.GetBackup` and `GPMBackup.GenerateReport` APIs). A CSV folder is insufficient. Require only the intended computer audit settings and precedence, with no unknown extensions, scripts, preferences, per-user audit entries or unrelated settings.

Use explicit domain and DC parameters for every operation. Check connectivity/authority before creation and do not treat an access error as an absent GPO. Choose a fresh unique name. For example, in an authorized lab using Windows PowerShell and the GroupPolicy module:

```powershell
# Replace these with the explicitly reviewed lab domain, DC, genuine backup and name.
$targetDomain = 'lab.example.test'
$targetDc = 'dc01.lab.example.test'
$genuineBackupRoot = 'C:\ReviewedGpoBackups'
$reviewedBackupId = [guid]'11111111-1111-1111-1111-111111111111'
$newName = 'WELA Audit - reviewed lab candidate'
$receiptPath = 'C:\Review\new-gpo-receipt.json' # Must not already exist.

if (Test-Path -LiteralPath $receiptPath) { throw 'Use a fresh receipt path.' }
$existing = @(Get-GPO -All -Domain $targetDomain -Server $targetDc -ErrorAction Stop |
  Where-Object DisplayName -eq $newName)
if ($existing.Count) { throw 'The target name already exists; stop without importing.' }

# Do not specify a Starter GPO or pipe to New-GPLink.
$created = New-GPO -Name $newName -Domain $targetDomain -Server $targetDc -ErrorAction Stop
[pscustomobject]@{
  Domain = $targetDomain; Server = $targetDc; GpoGuid = $created.Id
  Name = $created.DisplayName; BackupId = $reviewedBackupId
  State = 'Created; import and verification pending'
} | ConvertTo-Json | Out-File -LiteralPath $receiptPath -Encoding UTF8 -NoClobber -ErrorAction Stop

# Recheck that this exact new GPO is empty and unlinked before importing.
Get-GPOReport -Guid $created.Id -Domain $targetDomain -Server $targetDc -ReportType Xml
```

Stop and review the returned GUID, persisted receipt and actual report. Only after confirming that the exact new GPO remains empty and unlinked, execute this separate import step in the same reviewed session:

```powershell
Import-GPO -BackupId $reviewedBackupId -Path $genuineBackupRoot `
  -TargetGuid $created.Id -Domain $targetDomain -Server $targetDc -ErrorAction Stop
Get-GPOReport -Guid $created.Id -Domain $targetDomain -Server $targetDc -ReportType Xml
```

`New-GPO` creates an unlinked object and refuses a duplicate name. `Import-GPO` imports into the returned **new GUID**, without `-CreateIfNeeded`, name-based targeting or `Restore-GPO`. Importing settings preserves the destination's existing security filtering and links; it does not supply an approved scope of application. Review the actual result, including exact settings and continued absence of links, before considering any later link. Do not assume the backup's security filtering or role metadata protects the new GPO. [New-GPO](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/new-gpo?view=windowsserver2025-ps), [Import-GPO](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/import-gpo?view=windowsserver2025-ps).

If receipt persistence, import or readback fails, stop and retain the created GUID and evidence for manual review. Do not retry against an arbitrary existing GPO or automatically delete an object that another administrator may have changed or linked. This procedure is not a transaction or a lock against concurrent administrators; check the same DC immediately before each operation. Inspect both AD/SYSVOL versions and replication before proceeding beyond the unlinked candidate.

## Deployment acceptance and recovery

After separate approval of scope, stage any linking on an isolated test OU containing only representative disposable clients/servers. Plan role/build targeting and filtering explicitly; WELA's declared Role/Build is documentation, not a generated WMI or security filter. Check precedence, link order, enforcement, inheritance and resultant policy. No deployment link/force-refresh command is included here.

Record the genuine backup, target GUID, actual GPMC settings, RSoP/GPO source evidence, effective audit masks after ordinary policy processing, relevant SACL/service prerequisites, benign generated XML and collector arrival. Unlinked creation/import does not prove any client applied the settings. More specific or enforced policy can change the result. [Group Policy processing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-processing).

Rollback must be designed before linking. Preserve existing production GPOs and links throughout preparation. If testing fails, the policy owner should inspect and selectively reverse only the test changes, considering current links, authoritative settings and replication. Unlinking or deleting a GPO is not proof that all effective settings reverted. Retain evidence rather than blindly restoring an old whole-host policy snapshot. No audit-exhaustion test is required or provided.

WELA's automated tests validate package contents and unchanged host settings only. Genuine GPO creation/import, absence of unintended policy settings, AD/SYSVOL replication, client/DC/AD CS application and event/collection evidence remain pending lab acceptance for issue #2. Other WELA controls and Sysmon are outside this package.
