# Native local failed-logon probe

`failed-logon-probe` checks whether one fixed native local authentication failure can be correlated with its Security4625 event. It does not enable auditing. Sysmon is outside this workflow.

```powershell
.\WELA.ps1 failed-logon-probe
.\WELA.ps1 failed-logon-probe -FailedLogonAction Run -FailedLogonOutputPath C:\Evidence\failed-logon-01
```

The default Plan reads prerequisites and the actual latest Security record. It creates no files and makes no authentication attempt. Run requires a new private output directory and an elevated, unimpersonated 64-bit primary token. Existing Logon failure auditing, DWORD1 `SCENoApplyLegacyAuditPolicy`, an enabled/readable Security channel and running native observation/authentication services are prerequisites. Reviewed Windows11 and Server2022/2025 clients, standalone and member servers are accepted. Domain controllers are excluded because their account database is the domain database; native CI covers disposable workgroup Server2022/2025 under PowerShell5.1 and7, not client/domain policy variants.

Run generates a20-character account name from a fresh GUID and calls `NetUserGetInfo` against the local database. Only exact `NERR_UserNotFound` permits the next step. A fixed native `LogonUserW` call uses domain `.` (local account database only), network logon type3 and the NTLM provider2. A fixed public dummy string is not a real credential. There is exactly one attempt, with no retry, account creation, remote target or user-selected credential. The expected native result is failure1326. Any unexpected success closes the returned token without using it and remains unverified. The worker never impersonates.

The worker uses the current PowerShell executable and process-only execution-policy Bypass to load its fixed script. It has a20-second process bound. The optional `-FailedLogonTimeoutSeconds 1..30` controls event-delivery polling only; it never repeats authentication. Precise native UTC timestamps bound the actual authentication call without padding. A fresh Security record boundary, worker process/path, caller SID/logon session, exact generated account/domain, logon type/provider, and failure status/substatus must match exactly one provider/version0 Security4625. Provider schema differences, missing events, duplicate matches, denied reads, caps, token changes, policy/source/host/channel drift and a backwards record boundary remain unverified.

Evidence includes a durable `intent.json` before launching, the native receipt, before/after observations, exact raw XML, and a manifest with SHA256 artifact hashes. A timeout or failed receipt leaves the intent so an operator can see that an attempt may have occurred; absence of a successful report does not establish that no attempt happened. Record boundaries and hashes detect selected inconsistencies; they are not a tamper-proof log-continuity or machine-attestation mechanism. Keep the entire directory together. No policy, channel, service, account or trust configuration is written by the product.

The observed result proves this one local nonexistent-account failure only. It does not prove remote or domain authentication, real-account password failures, lockout handling, forwarding, SIEM parsing, every failed-logon variant or Sigma rule readiness. `ReadyRuleCredit` remains0. The attempt creates expected authentication telemetry and may be visible to local monitoring.

## Validation and references

Portable fixtures test exact100ns time boundaries, account/status/process/token mismatches, malformed XML, duplicate events, source drift, caps, failures and public CLI guards. The native workflow prepares only the disposable fixture's Logon failure mask and audit precedence, executes two independent public runs, validates actual4625 XML/receipt hashes, verifies unchanged local accounts and restores all59 audit masks and the original typed precedence.

Microsoft documents the local-domain behavior and native return contract in [LogonUserW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw), account lookup in [NetUserGetInfo](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusergetinfo), and the event fields/statuses in [4625: An account failed to log on](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625).
