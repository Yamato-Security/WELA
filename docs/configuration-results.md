# Verified configuration and recovery

`configure` reads live state, records each proposed write before executing it,
checks native exit codes, and reads the resulting state. It returns an object with
`ExitCode`, `DryRun`, `BackupPath`, `Failed`, `Skipped`, and a `Results` array.
`-ResultsPath` also saves that object as JSON. The command exits with status 1 when
any control fails or changes again before the final verification. A fatal preflight
or result-file error also exits with status 1.

```powershell
# Read live settings; do not change Windows settings, restart services or create a journal.
.\WELA.ps1 configure -DryRun -ResultsPath .\proposed-results.json

# Apply with interactive approval for each change, including the CA restart.
.\WELA.ps1 configure -BackupPath C:\WELA-Recovery\run-001 -ResultsPath .\results.json

# Apply the existing WELA choices without individual prompts.
.\WELA.ps1 configure -Auto -ResultsPath .\results.json
```

Keep the complete WELA directory, including `scripts/Configuration.ps1`. Choose a
recovery path whose parent directory is writable only by the operators who manage
these settings. The backup directory must not already exist. Without `-BackupPath`,
a unique directory is created beside WELA. `-Debug` does not substitute cached
audit policy data during configuration. `-DryRun` may write the explicitly requested
result file, but performs no Windows configuration writes.

| Status | Meaning |
| --- | --- |
| Applied | Write succeeded and immediate read-back matched. |
| AlreadyCompliant | The initial live value already met the requirement; no write. |
| Skipped | Dry run, operator decline, or no configured local CA. |
| Failed | State could not be read, journaling failed, write/restart failed, or verification failed. |
| Overridden | A value verified earlier became noncompliant by the final read. Cause is unknown. |

Unknown and unavailable channels are reported as failed observations rather than
silently claiming that logging is enabled. Partial runs and runs with skipped
controls do not claim universal success. Verification is an observation at that
moment; it does not prove future GPO persistence, event production, collection or
Sigma rule coverage. A zero exit code with skipped controls is not full compliance.

Audit policy reads use GUIDs and numeric flags from the Windows
[AuditQuerySystemPolicy API](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy).
`auditpol /get /r` contains localized labels and no numeric setting column; it is
not parsed as though it were `auditpol /backup` output. Registry writes use terminating errors and verify
both the value and registry type. Log sizes retain larger existing buffers. A CA
is detected from its configured registry state; certutil must succeed before a
restart is attempted, and the restart must return to Running. A stopped CA is not
started automatically. A restart failure remains failed even if the registry value
was already written.

## Recovery journal and rollback design

Each line of `before.jsonl` records the computer, timestamp, control identity,
requested setting and exact pre-change state. Registry entries include whether the
key/value existed and the previous registry type. Event-log entries capture size, mode or
enabled state; audit policies capture the numeric mask; CA entries also capture
service state. A journal write failure prevents that control's mutation. The
journal is per control, not a full system backup, and can contain records for failed
or declined downstream actions. Save the final result file alongside it.

This change provides a guarded **manual recovery procedure**, not an automatic
rollback command. Automatic bulk rollback could overwrite a later administrator or
GPO change and could interrupt certificate services. Before recovery:

1. Use an elevated shell on the journal's recorded computer. Review the specific
   failed or applied control and capture its current live state.
2. Compare current state with the recorded requested/verified after-state. If it
   differs, stop and determine whether another writer made an intentional change.
   Do not blindly replay a journal or restore an entire audit policy backup.
3. Restore only the intended controls, normally in reverse application order:
   - **EventLog:** `wevtutil sl <log> /ms:<previous-bytes>` or `/e:<previous-bool>`.
     Profile size/mode entries include a complete state object; see
     [event-log recovery](eventlog-settings.md#recovery) for mode flags and the
     fresh `ImmediatePreWrite` journal record. Review shrinking buffers, changing
     retention or disabling a channel before proceeding.
   - **AuditPolicy:** `auditpol /set /subcategory:{<guid>} /success:<enable|disable>
     /failure:<enable|disable>`. Previous mask bit 1 means success, bit 2 means
     failure. Restore that subcategory, not unrelated policy.
   - **Registry:** restore the previous value using its recorded registry type.
     If the value did not exist, remove only that value. Preserve unrelated values
     and never recursively delete a newly created parent key. Binary and multistring
     old values must be reconstructed with their original types from the JSON.
   - **CertificateService:** restore the active CA's previous AuditFilter value (or
     its original absence) and separately approve the necessary service restart.
     Do not start a CA that was deliberately stopped. A failed restart can leave
     the registry and running service out of sync; an operator must resolve this.
4. Check every native exit code and read the restored state. Keep the recovery
   commands and observations with the original journal.

A future automated rollback command should require the same host and control
identity, validate journal schema and allowlisted types, check current state against
recorded after-state, refuse unexpected drift, journal recovery itself, and require
explicit approval for CA restarts. It should never import the whole registry or
force a Group Policy setting. These are design constraints, not implemented claims.

## Testing

`tests/Test-ConfigurationResults.ps1` uses mock Windows APIs and disposable temp
journals. It exercises nonzero native exits and stderr, false-success writes,
read-back, idempotence, final drift, dry runs, journal failure, locale-independent native audit flags, and CA write/restart failure. It does not change Windows settings.
`tests/Test-ConfigurationReadOnlyWindows.ps1` runs real read-only Windows audit-policy API and `auditpol /get` queries
and a child `cmd.exe` diagnostic/exit test. CI runs both scripts in Windows PowerShell
5.1 and PowerShell 7. Mutating behavior still requires isolated Windows/CA lab
validation; mock and read-only tests do not establish end-to-end event production.

## NTLM policy integration

Outgoing and domain NTLM decisions use the same configuration context. `-DryRun`
prevents both writes, and actual changes are journaled with their original registry
types before execution. Applied values participate in the final drift check.
`PreserveOrAudit` preserves an existing outgoing deny (`2`) and unknown numeric
values, recording the reason as `Skipped`; explicit `Audit` and `Deny` remain
available through `-OutgoingNtlmMode`. Non-DC domain auditing is `Skipped`.
Unknown domain role, unreadable policy and failed writes produce `Failed` outcomes
and a nonzero overall result while allowing other controls to be assessed.
`tests/IntegrationNtlmConfiguration.Tests.ps1` exercises this composed behavior
using mocked registry/CIM calls and temporary journals only.

## Versioned profile integration

`configure -Profile <id>` uses the same dry-run, recovery-journal and verification
runner as the broader default `configure` command. Host role/build and all required
effective audit settings are validated before creating a journal or changing any
Windows setting. The Windows-defaults profile remains read-only.

```powershell
.\WELA.ps1 configure -Profile cis-win11-v4-l1 -DryRun -ResultsPath .\cis-plan.json
.\WELA.ps1 configure -Profile microsoft-sct-win11-24h2 -Auto -BackupPath C:\WELA-Recovery\sct-001 -ResultsPath .\sct-results.json
```

Exact recommendations set the named mask; minimum recommendations only enable
required flags and accept a compliant superset. They never disable an unrequested
flag, including one added by another writer between observation and application.
Omitted, Not Configured and non-applicable policies are preserved. Opt-in policies
require `-IncludeOptional`. Both result paths retain version, host role/build,
source identifiers and prerequisites such as SACLs; recording an enabled audit
subcategory does not claim its prerequisite was installed.

The result `Scope` is `native-windows-configuration` for default configure and
`advanced-audit-policy-and-precedence` for `configure -Profile`. `ProfileScope` describes the
advanced-policy subset within either result. `-PlanPath` remains available for
profile JSON output; `-ResultsPath` saves the verified configuration report.

This composed change depends on the outgoing/domain NTLM corrections, versioned
audit profiles and six additional native audit controls. It preserves their
selection behavior while adding shared execution and recovery reporting.
`tests/IntegrationProfileConfiguration.Tests.ps1` tests the composed command
paths without touching Windows policy, including exact/minimum behavior, concurrent
flags, unknown-state preflight, reference-only defaults, metadata and dry runs.

`-DryRun` is supported by `configure`, including its `-Profile` form, and by
`configure-eventlogs`. Other commands reject the flag before dispatch, so `configure-sacl -DryRun` and
`update-rules -DryRun` cannot silently perform their normal mutations.

Outgoing `PreserveOrAudit` checks the shared runner's fresh registry snapshot and
checks again after prompting and journaling, immediately before the value write.
Newly observed deny or unknown states are preserved or refused with an explicit
result; changing them requires an explicit `Audit` or `Deny` choice. Windows does
not provide an atomic compare-and-set through this registry provider, so a
concurrent writer after the final check remains outside this guarantee.
