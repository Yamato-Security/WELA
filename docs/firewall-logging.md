# Native Windows Firewall text logging

`firewall-logging` is a separate, opt-in command for the Domain, Private and Public packet/connection text logs. It changes only `LogAllowed`, `LogBlocked`, `LogMaxSizeKilobytes` and, when explicitly selected, `LogFileName`. It does not enable the firewall, change filtering defaults or rules, start/restart services, create directories, modify ACLs, configure WEF/SIEM ingestion, or install Sysmon. `-Profile` and `-Baseline` are rejected because those options select Security audit policy. No Sigma coverage increase is claimed.

Run in an elevated Windows PowerShell 5.1 or PowerShell 7 session with the built-in NetSecurity module:

```powershell
# Read effective and local policy, directory/service prerequisites, and the proposed target.
.\WELA.ps1 firewall-logging -FirewallAction Audit -ResultsPath firewall-audit.json
.\WELA.ps1 firewall-logging -FirewallAction Plan -ResultsPath firewall-plan.json

# Preview and then apply, retaining existing effective paths and larger size limits.
.\WELA.ps1 firewall-logging -FirewallAction Configure -DryRun -ResultsPath preview.json
.\WELA.ps1 firewall-logging -FirewallAction Configure -Auto -BackupPath .\firewall-before -ResultsPath firewall-results.json

# Explicit path conformance to the reviewed CIS v4.0.0 client/server benchmarks.
.\WELA.ps1 firewall-logging -FirewallAction Configure -FirewallPathMode CisV4 -Auto

# Select Microsoft's currently documented higher size recommendation if desired.
.\WELA.ps1 firewall-logging -FirewallAction Configure -FirewallMinimumSizeKiB 20480 -Auto
```

Audit and Plan both perform current-host, read-only assessment and include the desired configuration; Plan is not an offline plan or a file that can authorize later writes. `-ResultsPath` is the only output file for these commands. Configure dry run never changes Windows or creates a recovery directory; an explicitly requested results file is still written. An unknown/blocked prerequisite gives exit code 1, including in a dry run. A readable noncompliant Audit/Plan has `ChangeRequired` and exit code 0 (the assessment completed).

## Policy semantics

Both allowed and dropped logging switches must be exactly True. The default minimum is **16,384 KiB**, taken from the reviewed CIS Windows 11 Enterprise and Windows Server 2022 **v4.0.0** benchmarks. Larger effective or local limits are retained during writes. `-FirewallMinimumSizeKiB` accepts 16,384 through 32,767. Microsoft's logging guide now recommends at least **20,480 KB**; the default here does not claim to implement that higher recommendation.

The default `Preserve` path mode never writes `LogFileName`. `CisV4` explicitly selects `%SystemRoot%\System32\LogFiles\Firewall\domainfw.log`, `privatefw.log` and `publicfw.log`. This is exact path conformance, with environment variables expanded for comparison, and minimum size conformance. Microsoft's guide uses different per-profile filenames. Neither mode reduces a larger log size.

Reports retain `ActiveStore` (resultant effective policy) and `PersistentStore` (local policy), plus differing logging fields. Configure writes only PersistentStore, verifies ActiveStore after each change, and checks it again at completion. A local write overridden by GPO/MDM fails verification. A previously compliant setting that changes before the final check becomes `Overridden`; the run exits 1. These observations do not establish the current policy writer or guarantee persistence after a later policy refresh. An already compliant effective policy is accepted without manufacturing a local override.

Recovery snapshots include both stores. Preserve mode rejects an effective path that changed after planning, even before the initial recovery snapshot, and verifies access to the actual effective destination. Rerun the plan to assess a changed path. WELA rechecks both stores after confirmation and journaling, and refuses the write if logging settings changed meanwhile. Explicit `CisV4` migration instead checks the selected new destination. There is no atomic transaction with Group Policy; subsequent races remain detectable only through the following reads. A failed control does not stop the remaining profiles.

## Service permissions and operational limits

The log path must expand to an absolute local drive path. WELA checks the **mpssvc** service account is the documented LocalService account, that the service SID is enabled, and that the service is running. It inspects the destination directory and any existing log file for Modify rights assigned to the **NT SERVICE\mpssvc** SID, including inheritance to newly created files. It rejects reparse points and conservatively reports `Unknown` when deny ACEs, group-only grants, unexpected service identity, or read errors prevent that static check. Missing directories or a stopped service are `Blocked`. Both states prevent configuration.

WELA does not attempt to broaden ACLs, resolve arbitrary group membership, impersonate the service, or silently provision directories. Have an administrator provision an approved directory and service permissions, then rerun the plan. `VerifiedExplicitGrant` means the conservative static ACL check passed; it is **not** proof of effective token access, file creation, rotation, disk capacity or successful ingestion. The complete service token, filesystem filters and concurrent policy/ACL changes can still affect writes.

Each snapshot also reports the firewall profile's `Enabled` value. A compliant logging configuration on a disabled/inactive profile is preparation for that profile, not proof of traffic events. WELA never changes that enforcement state. Text logs and Security EVTX audit events are separate sources; increasing an EVTX buffer does not configure these text logs, and a WEF subscription alone does not collect arbitrary text files.

## Manual recovery

There is no automatic rollback. Preserve `before.jsonl` and the results JSON. Before recovery, review failed versus applied controls, concurrent operator changes and GPO/MDM ownership. Restore the **local** snapshot, not the effective snapshot; applied policy may continue overriding it. Example for one reviewed journal entry:

```powershell
$entries = @(Get-Content -LiteralPath .\firewall-before\before.jsonl | ConvertFrom-Json)
$entry = $entries | Where-Object { $_.Kind -eq 'FirewallTextLog' -and $_.Target.Name -eq 'Domain' } | Select-Object -First 1
if (-not $entry) { throw 'No Domain firewall recovery entry found' }
$old = $entry.Before.Local
Set-NetFirewallProfile -Name $entry.Target.Name -PolicyStore PersistentStore `
    -LogAllowed $old.LogAllowed -LogBlocked $old.LogBlocked `
    -LogMaxSizeKilobytes $old.LogMaxSizeKilobytes -LogFileName $old.LogFileName -ErrorAction Stop
Get-NetFirewallProfile -Name $entry.Target.Name -PolicyStore PersistentStore
Get-NetFirewallProfile -Name $entry.Target.Name -PolicyStore ActiveStore
```

Do not blindly replay a journal: a failed write can have left the old state untouched, and a later administrator change may be intentional. Restore other profiles individually after the same review. No enforcement or ACL restoration is needed because this command does not change them.

## Validation and remaining integration evidence

The automated suite uses mocked firewall writes and temporary recovery files to check all profiles, larger limits, path preservation/CIS selection, effective-versus-local conflicts, idempotence, journal ordering, unknown permissions, read/write errors, prompt races and final drift. Windows CI runs these checks under PowerShell 5.1 and 7, plus actual read-only ActiveStore/PersistentStore and ACL inspection and a dry run. It does not alter runner firewall policy or generate traffic.

Before closing issue #375, capture evidence from an isolated Windows client/server lab: OS build, PowerShell version, WELA commit, before/after JSON, effective/local settings and service ACLs. On each applicable active network profile, generate one benign allowed connection and one controlled blocked connection against a disposable endpoint, confirm corresponding `ALLOW`/`DROP` text records and timestamps, and confirm the expected source path and parser in the actual collector. Test log creation and rotation under the actual service token, policy refresh/override behavior, and manual recovery. Do not weaken production filtering to create this evidence. These traffic/rotation/ingestion tests remain unperformed; no end-to-end detection claim is made.

Sources: [Microsoft firewall logging configuration](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure-logging), [Get-NetFirewallProfile policy stores](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile?view=windowsserver2025-ps), [Set-NetFirewallProfile logging parameters](https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile?view=windowsserver2025-ps), and the version-pinned CIS references in [issue #375](https://github.com/Yamato-Security/WELA/issues/375).
