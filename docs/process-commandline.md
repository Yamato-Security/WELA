# Scoped Security 4688 command-line policy

`process-commandline` reads or enables only the native `ProcessCreationIncludeCmdLine_Enabled` DWORD under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit`. Its default Audit action is read-only. Configure is an explicit choice and requires an administrator; it does not invoke the broad `configure` workflow.

```powershell
./WELA.ps1 process-commandline -ResultsPath commandline-audit.json
./WELA.ps1 process-commandline -ProcessCommandlineAction Plan -ResultsPath commandline-plan.json
./WELA.ps1 process-commandline -ProcessCommandlineAction Configure -DryRun
./WELA.ps1 process-commandline -ProcessCommandlineAction Configure -Auto -BackupPath C:\WelaBackups\commandline-001 -ResultsPath commandline-result.json
```

The supported host processes are native 64-bit Windows PowerShell 5.1 and PowerShell 7. The policy applies to Windows process creation, including programs launched from either engine; it is independent of PowerShell script-block/module logging and transcription. Actual Windows build, product type, join state and domain role must agree. Reviewed build families are Windows 11 22000/22621/22631/26100/26200 and Server 2022/2025 20348/26100. WMI must already be running; the command does not start it. Unknown or contradictory observations refuse configuration. Role/build overrides, source-profile selection and other command options are rejected.

[Microsoft documents the exact registry mapping](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-auditsettings). The independent [Audit Process Creation prerequisite](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing) must have success auditing enabled to generate 4688. The report reads its effective mask and audit precedence separately, without changing either. `SuccessMissing` or `Unknown` remains visible even if the command-line DWORD is enabled. Policy values absent/0 require change; DWORD1 is already compliant. Other values/types are preserved as unknown. If needed, only the final `Audit` subkey may be created beneath the existing `System` policy key, without `New-Item -Force`.

Command-line arguments are recorded as plain text in Security events and can include passwords or personal data. Review access to the Security log and avoid passing secrets as arguments. This is a property of the requested logging setting, not a claim that WELA filters sensitive data.

Before a write, `before.jsonl` stores the exact typed prior value/absence and observed host/unrelated child-key state. A new backup directory is required. Plan-to-read and prewrite comparisons reject drift; immediate and final readbacks distinguish Applied, AlreadyCompliant, Skipped, Failed and Overridden. DryRun makes no registry or recovery-directory changes. Unknown reads, failed writes, journal failures and result serialization failures cannot report success. Operations are not an atomic transaction with GPO/MDM/other administrators. The winning policy source and future persistence remain unknown; the command neither refreshes GPO nor edits domain policy. Unrelated values/subkeys are preserved and checked, not replaced.

For manual recovery, protect the journal and results, verify which write completed and compare the current value with the recorded After state. Restore only this exact DWORD's original type/value or absence if no later policy owns the change. Remove a newly created key only when the journal proves prior absence and the current key is still empty. Never replace the whole System policy key or restore unrelated values.

## Native validation

The disposable hosted Windows test exercises the public CLI on actual standalone Server 2022/2025 under both engines: absent/disabled state, Plan, DryRun, one-value Configure, exact original journal, idempotence, native readback and separate missing-prerequisite reporting. The fixture independently prepares Process Creation success and audit precedence, then verifies that the public command leaves all59 masks, precedence, other values, Security channel and service states unchanged. A separate existing fixed `cmd.exe /d /c echo` probe collects a precisely matched 4688 with command line. Artifact hashes, source fingerprints, exact builds/engines and final cleanup are retained. The fixture restores typed policies/key absence and all original audit masks; failed cleanup fails CI.

The command itself generates no probe event. Policy compliance is not proof of event generation, forwarding, backend normalization or a complete Sigma rule. `ReadyRuleCredit=0`. Hosted standalone-server evidence does not establish Windows11, domain-member, DC, ADCS, GPO or cross-host behavior. Sysmon is out of scope. See the [4688 schema](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688) and [native validation guide](native-validation.md).
