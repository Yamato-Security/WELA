# Scoped outgoing NTLM auditing

`outgoing-ntlm` audits or configures only `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic`. The separate broad `configure` workflow retains its existing behavior. Use elevated 64-bit PowerShell for Configure on reviewed Windows 11 builds (22000/22621/22631/26100/26200) or Server 2022/2025 (20348/26100); observed role/build and the existing key are required. Role overrides are refused.

```powershell
./WELA.ps1 outgoing-ntlm -NtlmAction Audit -ResultsPath audit.json
./WELA.ps1 outgoing-ntlm -NtlmAction Plan -ResultsPath plan.json
./WELA.ps1 outgoing-ntlm -NtlmAction Configure -DryRun -ResultsPath preview.json
./WELA.ps1 outgoing-ntlm -NtlmAction Configure -Auto -BackupPath ./before -ResultsPath result.json
# Explicitly replace a previously reviewed Deny all value with auditing:
./WELA.ps1 outgoing-ntlm -NtlmAction Configure -OutgoingNtlmMode Audit -BackupPath ./before-reviewed -ResultsPath reviewed.json
```

The default `PreserveOrAudit` mode sets only DWORD **1 (Audit all)** when absent or DWORD0. Existing DWORD1 is already compliant. Existing DWORD **2 (Deny all)** is reported as `PreservedEnforcement` and skipped; exit0 for this preserved case does not mean auditing was enabled. Explicit `Audit` authorizes replacing a known DWORD2 with1. Unknown types/values fail without writes in either mode. `Deny` is refused by this scoped command. It never changes incoming/domain NTLM policy, exceptions, audit subcategories, channel settings, services, or authentication restrictions other than the explicit conversion of a known outgoing deny to audit.

Plan is a live read-only assessment, not an importable authorization file. Audit/Plan reject mutation options. Configure re-reads the actual host and typed value, journals before mutation, refuses pre-write drift, and verifies immediate/final readback. A race after the final pre-write read remains possible; these observations are not atomic with GPO or another administrator. RSoP is explicitly last-applied and potentially stale, never proof of the current registry writer. Skipped, Failed and Overridden results remain distinct. No automatic rollback occurs.

For manual recovery, inspect the selected successful result and its original `before.jsonl` entry. The original typed registry state is `Before.Policy`; preserve current policy ownership and review drift before restoring that one value/type or removing that value if it was originally absent. Never remove the parent MSV1_0 key or replay another journal kind. Failed/partial attempts require individual inspection. Keep the original journal and result together.

Native acceptance uses disposable unjoined Server2022/2025 hosts under PowerShell5.1/7, exercises actual absence/allow→audit, original journals, dry run, repeat, readback and exact cleanup. Existing enforcement and malformed values are never installed on a native runner merely for testing; portable regressions verify those preservation/refusal paths, prompt-time drift and failures. Native tests preserve incoming/domain policy, siblings/access descriptor, channels, service and all59 audit masks. Windows11/DC/ADCS acceptance, authentication behavior, representative NTLM events, GPO persistence and collector delivery remain separate work for #362. No Sigma credit is inferred. Built-in Windows only; Sysmon is excluded.

Microsoft distinguishes outgoing audit from deny, describes GPO precedence and identifies the NTLM Operational log for validation: [outgoing NTLM policy](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-outgoing-ntlm-traffic-to-remote-servers).
