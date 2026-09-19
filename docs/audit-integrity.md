# Audit integrity: local rights and audit failure policy

`audit-integrity` reads the direct local LSA assignments for **Generate security audits** (`SeAuditPrivilege`) and **Manage auditing and security log** (`SeSecurityPrivilege`), together with the typed `CrashOnAuditFail` value. The default action is read-only. Configuration is a separate opt-in action with an explicit reviewed source profile; normal `configure` and Security audit-policy profiles do not invoke it.

```powershell
./WELA.ps1 audit-integrity -ResultsPath integrity-audit.json
./WELA.ps1 audit-integrity -IntegrityAction Plan `
  -IntegrityProfile cis-server2022-v4-dc -ResultsPath integrity-plan.json
./WELA.ps1 audit-integrity -IntegrityAction Configure `
  -IntegrityProfile cis-win11-v4-l1 -DryRun -ResultsPath integrity-preview.json

# After reviewing the actual host, affected SIDs and application dependencies:
./WELA.ps1 audit-integrity -IntegrityAction Configure `
  -IntegrityProfile cis-server2022-v4-member `
  -Auto -BackupPath .\new-integrity-backup -ResultsPath integrity-result.json
```

Use a 64-bit Windows PowerShell 5.1 or PowerShell 7 process. Reads need sufficient LSA/registry access; access denial is `Unknown`, never an empty compliant assignment. Configure requires elevation. CIM observations determine the actual client, member-server, standalone-server or domain-controller role and build; conflicting or unreadable role evidence blocks configuration. AD CS is a separate observed `CertSvc` role and does not turn a member server into a DC. No source profile is currently mapped to a standalone server. Host `-Role`/`-Build` overrides, `-Profile`, `-Baseline` and HTML are rejected. Integrity-only options are rejected before unrelated command dispatch. Audit and Plan never change Windows policy; Configure `-DryRun` also creates no recovery directory.

## Reviewed sources and exact requested settings

The catalog at [`config/audit_integrity_profiles.json`](../config/audit_integrity_profiles.json) pins source/PDF or package/template SHA-256 hashes and the exact SCT GPO template path. These are selected historical sources, not a claim of the latest CIS edition or full baseline compliance. Profile identity is recorded separately from observed host policy. `SourceSetting=OmittedBySource` means preserve the observed value, not clear it, assume a Windows default, or copy a recommendation from another profile.

| Profile | Actual role/build scope | `SeAuditPrivilege` | `SeSecurityPrivilege` | `CrashOnAuditFail` |
| --- | --- | --- | --- | --- |
| `cis-win11-v4-l1` | Client, 22000–26100 | LOCAL SERVICE + NETWORK SERVICE | Administrators | DWORD 0 |
| `cis-server2022-v4-member` | Joined member server, 20348 | LOCAL SERVICE + NETWORK SERVICE | Administrators | DWORD 0 |
| `cis-server2022-v4-dc` | DC, 20348 | LOCAL SERVICE + NETWORK SERVICE | Administrators | DWORD 0 |
| `microsoft-sct-win11-24h2` | Client, 26100 | Omitted; preserve | Administrators | Omitted; preserve |
| `microsoft-sct-win11-25h2` | Client, 26200 | Omitted; preserve | Administrators | Omitted; preserve |
| `microsoft-sct-server2022-member` | Joined member server, 20348 | Omitted; preserve | Administrators | Omitted; preserve |
| `microsoft-sct-server2022-dc` | DC, 20348 | Omitted; preserve | Administrators | Omitted; preserve |
| `microsoft-sct-server2025-v2602-member` | Joined member server, 26100 | Omitted; preserve | Administrators | Omitted; preserve |
| `microsoft-sct-server2025-v2602-dc` | DC, 26100 | Omitted; preserve | **Omitted; preserve** | Omitted; preserve |

Principal identity uses SIDs rather than localized account names: LOCAL SERVICE `S-1-5-19`, NETWORK SERVICE `S-1-5-20`, BUILTIN\Administrators `S-1-5-32-544`. The CIS entries are exact sets for the selected two rights; every missing and extra SID is listed in the plan, with resolved names where available. Unresolved names do not discard a SID.

The reviewed CIS Windows 11 Enterprise v4.0.0 sections are **2.2.23**, **2.2.30**, **2.3.2.2**. Server 2022 v4.0.0 uses **2.2.31**, **2.2.38 (DC)** / **2.2.39 (member)**, and **2.3.2.2**. [Reviewed Windows 11 PDF](https://rayasec.com/wp-content/uploads/CIS-Benchmark/Microsoft-Windows-Desktop/CIS_Microsoft_Windows_11_Enterprise_Benchmark_v4.0.0.pdf), [reviewed Server 2022 PDF](https://rayasec.com/wp-content/uploads/CIS-Benchmark/Microsoft-Windows-Server/CIS_Microsoft_Windows_Server_2022_Benchmark_v4.0.0.pdf).

The Microsoft entries come from the respective computer/member/DC `GptTmpl.inf` in the [Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319) packages listed in the catalog. In particular, the **Server 2025 v2602 DC template omits all three settings**; its member template's Administrators assignment is not imported into the DC profile. Omission is a statement about those selected templates, not a statement that Microsoft recommends removing a privilege or that a deployment's other GPOs omit it. WELA applies only these selected local settings; it does not import SCT GPOs, run the SCT installation scripts or change domain policy.

Microsoft's general policy documentation is separate from SCT template contents. Its [Generate security audits guidance](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn221956(v=ws.11)) identifies LOCAL SERVICE and NETWORK SERVICE; [Manage auditing and security log guidance](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn221953(v=ws.11)) discusses Administrators and dependency review. General [audit failure guidance](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/audit-shut-down-system-immediately-if-unable-to-log-security-audits) discusses availability/completeness tradeoffs. WELA does not turn this general guidance into an omitted SCT value.

## Privilege removal and service dependencies

Plans always show proposed additions and removals. If either exact right has extra assigned principals, the entire Configure action is blocked unless the operator explicitly supplies `-AllowPrivilegeRemoval`. `-Auto` alone cannot authorize removal. The flag can also be supplied to Plan to preview an executable removal plan; it does not discover or certify application dependencies.

Review each affected SID before using that option. IIS application pools can require `SeAuditPrivilege`. AD FS can require its service identity and `NT SERVICE\ADFSSrv` / `NT SERVICE\DRS`. Exchange deployments can require the Exchange Servers group to retain `SeSecurityPrivilege` on DCs. Custom applications may have additional requirements. The command reports these exceptions but does not invent service-specific principal sets, automatically classify an extra principal as unnecessary, or grant substitute rights. Keep required exceptions and record a source deviation instead of using removal consent to break a service.

The native adapter uses local [`LsaEnumerateAccountsWithUserRight`](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaenumerateaccountswithuserright) and [`LsaEnumerateAccountRights`](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaenumerateaccountrights). These are direct assignments, not an expansion of nested groups or a test of every user's effective token. Updates use [`LsaAddAccountRights`](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaaddaccountrights) / [`LsaRemoveAccountRights`](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaremoveaccountrights) for **one named right and SID per operation**. Removal always uses `AllRights=false`. Other privileges, logon rights, account objects and local/domain group membership are not replaced or deleted.

## CrashOnAuditFail and verification

The exact value is `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\CrashOnAuditFail`. DWORD `0` is reported disabled, DWORD `1` enabled, an absent value as absent (not assumed equivalent to an explicit source value), and DWORD `2` as `RecoveryRequired`. Unknown values, non-DWORD types, read errors and missing LSA keys block configuration. **A value of 2 is never reset by this workflow.** It does not clear the Security log, deliberately exhaust audit capacity, enable crash-on-audit-failure, restart Windows or automate recovery. CIS profiles may explicitly set DWORD 0 after review; SCT omissions preserve the observed state.

Before any mutation, the shared configuration runner writes `before.jsonl` with the complete observed assignments, every affected account's full rights, the original registry type/value/absence and the selected plan. The native operation compares a fresh snapshot with the plan, rereads before each individual mutation, then verifies the expected result and all preserved account rights. A final read detects later drift. Journal failure prevents mutation; a write, readback or preservation failure stops remaining operations. This is not a transaction: a concurrent writer can act between checks, and an earlier successful operation can remain after a later failure.

JSON keeps the reviewed plan's **before** observations separate from `Results[].After`. `Applied` / `AlreadyCompliant` establish only the observed local assignment/registry checks for the selected profile, including preservation of source omissions. `Skipped` includes dry-run or declined changes. Exit 0 means no failed/overridden controls; a skipped run is not configuration evidence. Unknown or mismatched source/host state is blocked. An already compliant source profile that omits all three controls requests no changes and does not certify a secure privilege set.

Existing process tokens are not refreshed. A later logon/service restart can be needed for rights to affect a new token; WELA performs neither. GPO can overwrite local settings later, and these observations do not identify the winning GPO, establish persistence or modify the authoritative source. Verify resultant policy with the policy owner and test a fresh appropriate identity separately.

## Recovery and remaining lab evidence

Recovery is manual. Protect the backup directory as administrator policy evidence and retain the result JSON. Compare the journal's `Before`, requested operations, any recorded `After`, **current** LSA assignments and the authoritative policy source. A journal records intent/prior state; it is not proof every listed operation completed. Reverse only confirmed changes: add back a right removed by this run or remove a right added by this run for the same exact SID, leaving all other current rights untouched. Do not import an old whole-account privilege list or a whole `secedit` template over later changes. Restore only `CrashOnAuditFail`'s previous type/value or absence after determining that no newer policy or audit-failure recovery state supersedes it; never blindly overwrite a current value of 2. Re-read policy afterward. No automatic rollback is offered because concurrent administrative changes and recovery state require review.

The focused suite mocks every mutation and covers exact source sets/omissions, role contradictions, removal consent, typed values, idempotence, journal failure, plan/prewrite races, partial failure, read errors, preservation of unrelated privileges and final drift. Windows CI is read-only on Server 2022/2025 under Windows PowerShell 5.1 and PowerShell 7: it compiles the native adapter, reads real LSA/CIM/registry state, compares assignments to a `secedit /export` in an owned temporary directory, and confirms unchanged observations. It does not grant/revoke any live rights or change the audit failure policy.

Remaining acceptance evidence requires disposable, snapshotted client/member/DC labs, including member/DC AD CS and relevant IIS/AD FS/Exchange dependencies: review affected principals, apply the chosen source profile, verify new-token behavior, readback after ordinary GPO refresh, benign audit generation and authorized collection, and selective recovery with unrelated rights preserved. Do not create an audit-exhaustion test. DC/member mutation, service-token and event/ingestion evidence is still pending; read-only CI cannot close those requirements.

This is audit-integrity hardening, not a new event family. Reports set `SigmaEvtxCredit=0`; no rule-eligibility or Sigma coverage increase is inferred. Sysmon is outside this native Windows workflow.
