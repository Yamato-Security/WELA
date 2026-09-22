# Version-aware native SMB audit policies

The opt-in `smb-auditing` command audits, plans and configures six built-in Windows audit policies. It does not enable insecure guest access, weaken signing/encryption, change SMB dialects or shares, restart services, or install Sysmon. It does not configure event forwarding, change channel settings or claim a Sigma coverage increase.

Run in elevated **64-bit** Windows PowerShell 5.1 or PowerShell 7:

```powershell
.\WELA.ps1 smb-auditing -SmbAction Audit -ResultsPath smb-audit.json
.\WELA.ps1 smb-auditing -SmbAction Plan -ResultsPath smb-plan.json
.\WELA.ps1 smb-auditing -SmbAction Configure -DryRun -ResultsPath smb-preview.json
.\WELA.ps1 smb-auditing -SmbAction Configure -Auto -BackupPath .\smb-before -ResultsPath smb-results.json
```

`-Profile` and `-Baseline` are rejected for this command: their advanced Security audit-policy semantics do not include these SMB policies. Audit and Plan both read the current host and show desired DWORD values; the plan is evidence, not an offline authorization file. They write only the explicitly requested results JSON. Configure dry run performs no policy/key writes and creates no recovery directory. Unknown read failures give exit code 1; known unsupported controls are skipped explicitly. Audit/Plan uses `PolicyConfigured` for the desired registry DWORD, with runtime state reported separately. A readable assessment with `ChangeRequired` has exit code 0 because the assessment completed. `Applied` and `AlreadyCompliant` rows verify the requested policy-registry DWORD. Exit code 0 means there are no failed/overridden controls; dry-run, declined and unsupported/skipped controls do not establish configuration. None of these results proves runtime auditing or event generation.

## Exact controls and capability gates

Each value below is enabled as **REG_DWORD 1**. Numeric strings are neither compliant nor accepted during read-back.

| Registry key under HKLM | Values |
| --- | --- |
| `SOFTWARE\Policies\Microsoft\Windows\LanmanServer` | `AuditClientDoesNotSupportEncryption`, `AuditClientDoesNotSupportSigning`, `AuditInsecureGuestLogon` |
| `SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation` | `AuditServerDoesNotSupportEncryption`, `AuditServerDoesNotSupportSigning`, `AuditInsecureGuestLogon` |

The reviewed build families are Windows 11 24H2 (26100), Windows 11 25H2 (26200), and Windows Server 2025 including domain controllers (26100). Host role/build is read from Win32_OperatingSystem. Older releases, including Server 2022 (20348), are `NotApplicable` even if someone has copied newer ADMX files onto them. Unreviewed future builds or unknown host information are `Unknown`; they receive no policy writes.

A qualifying build is only a candidate. For **each** control WELA must also read the local `%windir%\PolicyDefinitions\LanmanServer.admx` or `LanmanWorkstation.admx` and find exactly one matching Machine policy, official `Pol_...` name, exact registry key and value name, and enabled decimal DWORD value 1. Missing, inaccessible, malformed, mismatched or ambiguous definitions are `Unknown`. DTD/external entities are prohibited. The report records the local ADMX path, SHA-256 hash and supportedOn reference. WELA does not download templates or assume that a Central Store proves local capability.

Microsoft's Policy CSP pages list **26100.3613** as the availability floor for that CSP delivery surface. This tool writes the documented registry policy, not the CSP. It does not treat every 26100 host as supported based on its build alone or use the CSP minor build as a substitute for local policy/capability evidence. Local templates can still be replaced independently of the OS; available native runtime properties and lab events provide additional evidence.

## Policy registry versus effective runtime

The separate explicit [`smb-runtime` activation command](smb-runtime-activation.md) can activate the six native audit Booleans through reviewed SMB setters, with policy-conflict and complete configuration guards. This policy command does not invoke it automatically. Both operations keep event generation and policy persistence separate from current configuration observations.

Reports keep `Policy` (the actual policy-registry value/type) separate from `Runtime` (the corresponding property of `Get-SmbServerConfiguration` or `Get-SmbClientConfiguration`). WELA never substitutes the policy DWORD for a runtime observation:

- `Observed`: the getter exposes an actual Boolean. `RuntimeState=Active` means that Boolean was True, not that representative events were generated. False is `NotActive` before the desired policy exists, or `PendingVerification` when the policy registry contains DWORD 1. A correctly written/read-back policy therefore succeeds even when the runtime Boolean remains False. Pending verification does **not** assert propagation delay, a future activation deadline, or that a policy refresh/restart will fix the discrepancy. Its cause and activation timing are unknown; investigate and repeat Audit independently. WELA performs no refresh/restart and never weakens security to make a Boolean change.
- `NotExposed`: the getter or property is unavailable. `RuntimeState=Unknown` distinguishes this from an observed False. With the exact local ADMX mapping, WELA can verify the registry policy only. The snapshot explicitly says **effective auditing not established**. A successful registry result is not proof of runtime activation or event generation.
- `Unknown`: a runtime read fails or returns an unexpected type. Configuration fails closed without treating the state as a default.

Configure uses the common recovery journal and result runner. It rechecks capabilities/current values before writing, verifies the DWORD afterward, and reads policy/runtime again at completion. Registry value/type drift becomes `Overridden`; actual read/write failures remain failures and give a nonzero exit code while other controls continue. A runtime Boolean that remains or becomes False is reported separately as pending verification, rather than a registry write failure. An existing DWORD 1 is not rewritten merely to try to make the runtime Boolean change. A later audit can observe `Active` without any additional writes. A prompt-time policy change is refused so recovery evidence does not silently describe a stale value.

Configure JSON includes an explicit `VerificationScope` and `RuntimeVerification` counts for Active, PendingVerification, NotActive, Unknown and NotApplicable, alongside each actual before/after observation. Failed controls count as Unknown in that summary so an older snapshot cannot be mistaken for a successful final runtime read. Console output scopes success to policy-registry verification and prints the runtime counts. None of these statuses proves event generation or central collection.

The registry policy is a current observation, not proof of GPO/MDM ownership or long-term persistence. Future policy refresh can replace it. A direct local policy write also is not an edit to the domain GPO or its authoritative registry.pol source.

## Manual recovery

There is no automatic rollback. Review results and `before.jsonl` before selecting an entry. Its `Before.Policy` contains the original value existence, data and registry kind; `Before.Runtime` is observation only and must not be blindly passed to SMB setters. Example for one reviewed entry:

```powershell
$entry = Get-Content -LiteralPath .\smb-before\before.jsonl | ConvertFrom-Json |
    Where-Object { $_.Kind -eq 'SmbAudit' -and $_.Target.Name -eq 'AuditClientDoesNotSupportSigning' } |
    Select-Object -First 1
if (-not $entry) { throw 'Recovery entry not found' }
$old = $entry.Before.Policy
if ($old.ValueExists) {
    Set-ItemProperty -LiteralPath $entry.Target.Path -Name $entry.Target.Name -Value $old.Value -Type $old.Type -ErrorAction Stop
} else {
    Remove-ItemProperty -LiteralPath $entry.Target.Path -Name $entry.Target.Name -ErrorAction Stop
}
```

Review concurrent administrator changes and GPO/MDM ownership first; a failed write may have left the original state unchanged. Restore controls individually and rerun Audit. Keep newly created parent policy keys unless separately reviewed as empty and safe to remove; never delete the entire LanmanServer/Workstation policy key. Registry and runtime observations can differ, and this implementation has not established why or when they converge; recovery also requires a later runtime check. This command has not changed guest access, signing/encryption requirements, shares or service state.

## Evidence still needed before closing issue #377

Mocked tests exercise OS/build and per-policy ADMX gating, all six exact policy targets, DWORD types, supported/unsupported/unknown states, runtime read errors and unavailable properties, dry run, recovery ordering, idempotence, pending runtime verification despite successful DWORD writes, later runtime activation without rewriting, actual runtime read failures and final registry drift. Windows CI adds read-only registry/local-ADMX/native-runtime observations and dry-run checks under PowerShell 5.1 and 7. It does not generate SMB traffic or alter runner policy.

On isolated supported client/server snapshots, retain OS build/revision, PowerShell version, WELA commit, ADMX hashes and before/after reports. Confirm a policy refresh does not unexpectedly override the requested setting. Capture representative native SMB audit events under the existing security requirements and verify collector delivery. Microsoft's signing/encryption guide identifies SMBClient/Audit 31998/31999 and SMBServer/Audit 3021/3022; validate the event actually corresponds to the test condition. Inspect guest-audit behavior without enabling guest access or weakening signing/encryption. If the existing secure configuration prevents a guest-session event, record that limitation rather than changing the security posture merely to obtain a test event. Also verify manual recovery. These traffic and ingestion tests remain pending; keep the issue open until the required evidence exists.

Microsoft documents the policy-to-registry mappings and the SMB configuration cmdlets, but the cited pages do not establish synchronous propagation of a direct policy-registry write into the getter or promise that refreshing Group Policy resolves any discrepancy. WELA makes neither assumption.

Sources: [LanmanServer Policy CSP mappings](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-lanmanserver), [LanmanWorkstation Policy CSP mappings](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-lanmanworkstation), [SMB signing and encryption auditing](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview), [SMB feature availability](https://learn.microsoft.com/en-us/windows-server/storage/file-server/file-server-smb-overview), [SMB configuration getter](https://learn.microsoft.com/en-us/powershell/module/smbshare/get-smbclientconfiguration?view=windowsserver2025-ps), [SMB server audit parameters](https://learn.microsoft.com/en-us/powershell/module/smbshare/set-smbserverconfiguration?view=windowsserver2025-ps), and [issue #377](https://github.com/Yamato-Security/WELA/issues/377).

## Native public configuration acceptance

The separately opted-in `SmbPolicyConfigure.Windows.Tests.ps1` fixture runs public Plan, DryRun and Configure on disposable, unjoined Server 2022/2025 hosts with PowerShell 5.1/7. Server 2022 must skip all six unsupported controls without policy writes. On Server 2025, exact local ADMX and runtime observations must qualify before preparing six DWORD 0 values. Public Configure then writes six DWORD 1 values, preserves full native SMB configuration, siblings, access descriptors, service state and all 59 audit masks, records exact typed original journals, and repeats without writes. Cleanup restores the original values and removes only fixture-created empty policy keys. Native results retain the actual build/UBR and PowerShell version.

This acceptance establishes policy registry behavior only. It generates no SMB traffic, performs no runtime activation or policy refresh, and does not establish Windows client/DC/AD CS, event, forwarding or Sigma readiness.
