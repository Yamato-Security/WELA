# Explicit native SMB audit activation

Related to #377. `smb-runtime` explicitly activates the six reviewed native SMB audit switches when their actual runtime Booleans are False. It complements `smb-auditing`, which configures policy DWORDs and reports runtime state separately. Sysmon is excluded.

```powershell
.\WELA.ps1 smb-runtime
.\WELA.ps1 smb-runtime -SmbRuntimeAction Activate -DryRun
.\WELA.ps1 smb-runtime -SmbRuntimeAction Activate -SmbRuntimeOutputPath C:\Evidence\new-smb-activation -Auto
```

The default Plan and Activate dry-run only read. Activate requires a new evidence directory outside the source tree on a local fixed drive with an existing parent. It protects that directory for the actual user, Administrators and SYSTEM. Without `-Auto`, each required change asks for explicit consent. Existing True flags are checked without invoking their setters. Activation requires permissions to use the native SMB configuration cmdlets.

Only native 64-bit Windows 11 24H2/25H2 (builds 26100/26200) and Server 2025 (26100, including DC product type) are reviewed. Each switch also requires the exact local machine ADMX mapping, genuine Windows `SmbShare` module location, an actual Boolean setter parameter and a native CIM Boolean getter property. Missing definitions, properties, unsupported builds, unreadable values and unexpected configuration types stop the operation. Windows 11 and DC deployment acceptance remain separate from hosted member-server testing.

| Native command | Only permitted parameters |
| --- | --- |
| `Set-SmbServerConfiguration` | `AuditClientDoesNotSupportEncryption`, `AuditClientDoesNotSupportSigning`, `AuditInsecureGuestLogon` |
| `Set-SmbClientConfiguration` | `AuditServerDoesNotSupportEncryption`, `AuditServerDoesNotSupportSigning`, `AuditInsecureGuestLogon` |

Every selected value is set to Boolean True, one at a time. The command does not set signing/encryption requirements, enable guest access, modify shares, change services, restart Windows, refresh policy, change channels or generate traffic. It changes no registry-policy value. A current absent policy value is compatible and stays absent; a present policy must be DWORD 1. Any conflicting or malformed policy blocks the entire activation before writes. Absence does not establish local ownership or rule out future GPO/MDM changes. This is an explicit local runtime configuration operation, not a GPO edit or a promise of persistence.

The plan captures all six typed policy tuples, local ADMX hashes, host/build identity, native module/source fingerprints and every supported property exposed by both native configuration getters. Before each setter, WELA compares the complete current snapshot, writes and flushes a Pending receipt to disk, then checks the snapshot again after any prompt. The only permitted readback difference is that single audit Boolean becoming True. Every other native configuration property and policy tuple must remain unchanged before a Confirmed receipt is written. A final complete readback is required for `RuntimeAuditingActive`.

The evidence directory retains `plan.json`, numbered Pending/Confirmed receipts and `result.json`. Failure, drift, declined changes or incomplete readback produce a nonzero result. After a failed operation, remaining flags are skipped; earlier successful changes stay recorded. A setter may have changed its flag before throwing or before a receipt failure, so Pending alone is not proof of either success or no change. There is no automatic rollback. Reports and hashes establish observed consistency, not historic authenticity or protection against an administrator replacing the evidence. No atomic lock against concurrent Windows policy/configuration writers is claimed.

For manual recovery, select one original flag and compare its Pending/Confirmed receipts with fresh native configuration and policy. Restore only that flag's original Boolean through the matching native setter after reviewing concurrent changes and policy authority. Do not replay the entire configuration object or copy getter values into arbitrary setter parameters. Retain the recovery readback separately. Restoring a getter value does not prove the exact historical registry representation or future policy persistence.

**Runtime activation grants zero Sigma readiness credit.** The command neither generates nor verifies representative SMB events, forwarding, a backend query, guest behavior or persistence after policy refresh. Keep #377 open until its remaining secure-peer event and ingestion acceptance is completed; never weaken signing/encryption or enable guest access solely to manufacture test evidence.

Focused tests exercise typed configuration, policy conflicts, idempotence, durable-receipt failure, prompt/prewrite/final drift and partial native failures. The explicitly gated disposable GitHub VM fixture prepares only these audit flags as False on Server 2025, invokes the public CLI to activate all six, checks dry-run/idempotence and restores their original native values. It compares every other exposed native configuration property, all policy tuples and source context before/after. Server 2022 tests actual unsupported refusal. Both run under Windows PowerShell 5.1 and PowerShell 7. The fixture performs no SMB traffic or policy changes, and must never run on production.

Microsoft sources: [SMB client audit parameters](https://learn.microsoft.com/en-us/powershell/module/smbshare/set-smbclientconfiguration?view=windowsserver2025-ps), [SMB server audit parameters](https://learn.microsoft.com/en-us/powershell/module/smbshare/set-smbserverconfiguration?view=windowsserver2025-ps), [signing and encryption audit events](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview), [LanmanServer policy mappings](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-lanmanserver), [LanmanWorkstation policy mappings](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-lanmanworkstation).
