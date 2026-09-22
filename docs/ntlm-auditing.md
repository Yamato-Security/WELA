# Scoped incoming and domain NTLM auditing

`ntlm-auditing` reads or configures two distinct audit values without invoking the broad `configure` workflow. It never writes an NTLM restriction or exception. Configure requires an explicit selection and elevated native 64-bit PowerShell on reviewed Windows 11 builds 22000/22621/22631/26100/26200 or Server 2022/2025 builds 20348/26100. Product type, domain role and join state must agree; role/build overrides are refused. Winmgmt must already be running before any CIM observation.

| Selection | Exact value | Requested setting | Applicability |
| --- | --- | --- | --- |
| Incoming | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\AuditReceivingNTLMTraffic` | DWORD 2, audit all accounts | Reviewed client and server roles |
| Domain | `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\AuditNTLMInDomain` | DWORD 7, Enable all | Actual domain controller only |
| Both | Both rows above | Each applicable audit setting | Domain row remains NotApplicable on a non-DC |

```powershell
./WELA.ps1 ntlm-auditing -NtlmAuditAction Audit -ResultsPath audit.json
./WELA.ps1 ntlm-auditing -NtlmAuditAction Plan -NtlmAuditScope Incoming -ResultsPath plan.json
./WELA.ps1 ntlm-auditing -NtlmAuditAction Configure -NtlmAuditScope Incoming -DryRun -ResultsPath preview.json
./WELA.ps1 ntlm-auditing -NtlmAuditAction Configure -NtlmAuditScope Incoming -Auto -BackupPath ./before-incoming -ResultsPath incoming.json
# Run on the reviewed domain controller itself:
./WELA.ps1 ntlm-auditing -NtlmAuditAction Configure -NtlmAuditScope Domain -BackupPath ./before-domain -ResultsPath domain.json
```

Incoming accepts native DWORD 0/1/2 or an absent value. Domain accepts absent or DWORD 0/1/3/5/7, plus historical WELA DWORD 2 for migration to7. The report labels2 `LegacyValue2`; it does not invent its undocumented meaning or credit it as full auditing. All other values/types are refused. Existing parent keys are required. An absent audit value does not imply a measured clean-image default.

Audit and Plan are live read-only assessments. Plan is not an importable authorization file. Configure re-reads the actual host and typed selected state, writes an original `before.jsonl` receipt before mutation, checks for drift after consent, and verifies immediate and final readback. Applied, AlreadyCompliant, Skipped, Failed and Overridden remain distinct. Partial failures return nonzero even if another selected row succeeded. A skipped non-DC domain row can coexist with exit0; this means domain configuration was not applicable, not that domain auditing was enabled. RSoP matches are last-applied observations from `RSOP_RegistryValue`, may be stale or incomplete, and do not prove current ownership or persistence. The registry write is not atomic with GPO or another administrator.

Outgoing policy is managed separately by [outgoing-ntlm](outgoing-ntlm.md). This command preserves outgoing/incoming/domain restrictions, NTLM exceptions, channels, services and advanced audit masks. It does not authenticate, create domain objects, restart services, refresh GPO, or generate NTLM events. Registry compliance alone supplies no forwarding or Sigma credit. Sysmon is out of scope.

For manual recovery, retain the successful selected result and original journal. Review `Before.Policy` and current ownership/drift before restoring that exact typed value, or removing only that value if originally absent. Never remove the parent key, replay another control's receipt, or treat a failed/partial attempt as a confirmed configuration. No automatic rollback occurs.

Native acceptance uses disposable unjoined Server 2022/2025 under Windows PowerShell 5.1 and PowerShell 7. It exercises actual incoming absence/disabled/domain-account-only→all-account auditing, dry run, original journals, repeated Configure, actual non-DC Domain/Both skips, and independent preservation/cleanup. Portable tests exercise DC transitions including historical2, unknown values/types, conflicting hosts, prompt drift, write/readback errors and partial outcomes. Windows 11, joined member/CA, actual DC application, domain authentication/events, policy persistence and collector delivery remain separate acceptance work for #363.

Microsoft documents [incoming values0/1/2](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-localpoliciessecurityoptions#networksecurity_restrictntlm_auditincomingntlmtraffic) and the [domain audit policy's DC applicability and separation from blocking](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-audit-ntlm-authentication-in-this-domain). Domain 7 follows the already reviewed WELA domain-audit correction and its pinned baseline evidence; this addition isolates that setting into a dedicated command.
