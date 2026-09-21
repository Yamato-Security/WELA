# Guarded firewall text-log recovery

`firewall-recovery` plans and explicitly restores the four local logging fields for **one** Domain, Private or Public profile from a completed WELA `firewall-logging -FirewallAction Configure` operation. It uses built-in Windows functionality; Sysmon is out of scope. It does not grant event-generation, delivery, retention or Sigma readiness credit.

The restored fields are `LogAllowed`, `LogBlocked`, `LogMaxSizeKilobytes` and `LogFileName` in `PersistentStore`. The original values can disable logging or reduce its size: review the complete proposed tuple before restoring. Microsoft distinguishes local persistent settings from the resultant `ActiveStore` policy. Recovery reports the selected effective tuple separately and does not change its policy authority. See [Set-NetFirewallProfile](https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile?view=windowsserver2025-ps).

## Prepare and review

Keep the genuine original `before.jsonl` and final results from [firewall logging configuration](firewall-logging.md). The selected row must have final status `Applied`, dedicated scope `firewall-text-logging-only`, a matching version-1 journal entry and matching original Before/Desired/Target values. Failed, partial, ambiguous and no-op operations are not automatically recoverable.

Use elevated native 64-bit Windows PowerShell 5.1 or PowerShell 7 on reviewed Windows 11 builds 22000/22621/22631/26100/26200 or Server 2022/2025 builds 20348/26100. Winmgmt, MpsSvc and BFE must already be running before native provider reads. The plan and restoration must use the same engine version, machine identity and actual elevated operator/logon context. Impersonation is refused. Original version-1 configuration journals recorded only the computer name, so they do **not** prove historical MachineGuid or operator identity. The operator must establish that the original evidence belongs to this installation; current identity binding starts with the recovery plan.

Create new local output directories under an existing parent, outside the WELA source tree. WELA applies private output permissions and never overwrites an old evidence directory.

```powershell
./WELA.ps1 firewall-recovery -FirewallRecoveryProfile Domain `
  -FirewallRecoveryJournalPath C:\Evidence\configure-backup\before.jsonl `
  -FirewallRecoveryResultsPath C:\Evidence\configure-results.json `
  -FirewallRecoveryOutputPath C:\Evidence\firewall-recovery-plan
```

Review `plan.json`, especially `Control.Expected` (the confirmed original local After values), `Control.RecoverTo` (the exact original local Before values), the selected profile, source hashes and preserved settings. Record the reported `PlanSha256` after review. Plan reads configuration and writes evidence only.

```powershell
# Replace this placeholder with the SHA256 from the reviewed plan.
$reviewedHash = '<64 lowercase hexadecimal characters>'
./WELA.ps1 firewall-recovery -FirewallRecoveryAction Restore `
  -FirewallRecoveryPlanPath C:\Evidence\firewall-recovery-plan\plan.json `
  -FirewallRecoveryPlanHash $reviewedHash -DryRun

./WELA.ps1 firewall-recovery -FirewallRecoveryAction Restore `
  -FirewallRecoveryPlanPath C:\Evidence\firewall-recovery-plan\plan.json `
  -FirewallRecoveryPlanHash $reviewedHash `
  -FirewallRecoveryOutputPath C:\Evidence\firewall-recovery-result
```

Restoration prompts before the single native setter. `-Auto` explicitly skips that prompt; it does not skip any evidence or state guards. Dry run creates no output directory and does not call a setter. An exact already restored tuple returns `AlreadyRestored` without another write.

## Guards and outcomes

WELA independently rebuilds the selected operation from unchanged journal/result bytes and checks the separately supplied plan hash. It accepts explicit local `True`/`False` logging flags, an integer size from 1 through 32767 KiB and an ordinary local path. Only `%SystemRoot%` and `%windir%` variables are supported. UNC/device paths, alternate streams, dot segments, wildcards, reparse paths and unknown values are refused. `NotConfigured` is documented for GPO use and requires manual review instead of automatic local replay. The original command's Preserve/CisV4 path and maximum-size behavior must explain the recorded After tuple exactly.

The current local tuple must equal the selected confirmed After tuple, or the exact original tuple for idempotence. A new plan binds current host/operator context, source files and native NetSecurity module files. It preserves the other two profiles in both stores, every nonlogging field of the selected profiles, and bounded native rule/filter configuration fingerprints. Filters are queried separately because conditions are exposed through filter objects; see [Get-NetFirewallPortFilter](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallportfilter?view=windowsserver2025-ps). Inventories cap each class/store at 4096 objects and 16 MiB of canonical data. Unknown native property types, unreadable inventories or caps refuse recovery. Volatile rule operational diagnostics are excluded from configuration fingerprints.

After a durable `pending.json` receipt, WELA rechecks inputs and current state before the one fixed `Set-NetFirewallProfile -PolicyStore PersistentStore` call. It then verifies the exact local tuple, preserved configuration and fresh/final context, retaining `confirmed.json` and `result.json`. It never changes firewall enforcement, rule definitions, other profiles, Group Policy, destination ACLs, services or shares. There is no automatic rollback.

| Result | Meaning |
| --- | --- |
| `Planned` / `WouldRestore` | Reviewable plan / read-only current guard checks passed. |
| `LocalLoggingRestored` | Exact selected local tuple and preserved configuration passed readback and final checks. |
| `AlreadyRestored` | Original local tuple is already present; no setter was called. |
| `Refused` | A prerequisite or guard failed before a setter was attempted. |
| `WriteAttemptedUnverified` | A setter was attempted but completion or subsequent verification failed. Preserve the receipts and investigate manually. |

`EffectiveMatchesLocal` compares the selected effective and local tuples after restoration. False can represent an effective policy override; local success does not imply effective logging was restored. Destination write authorization, actual firewall text records, future policy refresh, forwarding and long-term retention need separate acceptance. Path checks do not prove destination writability or historical file identity. Native APIs do not offer an atomic transaction over all these inventories: observed drift fails closed, but concurrent external changes between reads cannot be excluded.

## Validation

Focused fixtures cover strict original evidence, typed values, changed plans, stale settings, operator/source drift, post-prompt changes, partial writes, preserved enforcement and local/effective separation. The gated disposable Windows workflow uses the public Configure command to produce genuine journals, then public Plan, dry run, drift refusal, Restore and idempotence on Server 2022/2025 under both engines. Its fixture changes only logging values and a new owned log directory, restores all original logging fields, and compares complete preserved native configuration before removing that directory. It never generates traffic or changes enforcement. Windows 11, domain policy refresh and backend acceptance remain separate deployment tests.
