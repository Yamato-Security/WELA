# Native AD CS auditing

`adcs-auditing` observes or configures the audit settings of an existing, dedicated Windows Server 2022/2025 certification authority. Its default action is read-only. It never installs a CA, submits a request or approves a certificate. Sysmon is excluded.

```powershell
.\WELA.ps1 adcs-auditing -ResultsPath C:\Evidence\ca-audit.json
.\WELA.ps1 adcs-auditing -AdcsAction Plan -AdcsProfile microsoft-identity-ca-2026-09
.\WELA.ps1 adcs-auditing -AdcsAction Configure -AdcsProfile microsoft-identity-ca-2026-09 -DryRun
# In an approved CA maintenance window, on a CA that is already running:
.\WELA.ps1 adcs-auditing -AdcsAction Configure -AdcsProfile microsoft-identity-ca-2026-09 -AllowRestart -Auto -BackupPath C:\Evidence\ca-journal -ResultsPath C:\Evidence\ca-result.json
```

The report parent must already exist on a local fixed drive. Results and backup paths must be new; existing files and reparse-point directories are refused. Dedicated configuration protects its new journal directory for the current user, SYSTEM and Administrators. Use a suitably protected existing parent for the JSON report.

## Source and prerequisites

The explicit `microsoft-identity-ca-2026-09` profile selects native CA requirements from [Microsoft Defender for Identity event collection guidance](https://learn.microsoft.com/en-us/defender-for-identity/deploy/event-collection-overview): Certification Services Success and Failure, `AuditFilter=127`, and a Certificate Services restart after changing that filter. The shared advanced-audit source is `microsoft-identity-reviewed-2026-09`; its file fingerprint and canonical Certification Services GUID are checked again before changes. `SCENoApplyLegacyAuditPolicy=1` is verified before the advanced subcategory, and both audit prerequisites are verified before changing the CA. This is a CA audit component, not a complete MDI deployment or baseline.

The native observation records the exact build/patch/edition and machine role, Active CA name and registry path, CA type, configured CA certificate hashes and public certificate fingerprints, typed filter and precedence values, effective normalized audit mask, and Certificate Services process/start time/dependents. Configured certificate identities must resolve in LocalMachine/My. The configuration target is the pinned registry child, rather than an implicit `certutil CA` target that could change between planning and execution.

An absent local CA is `NotApplicable`. An unreadable or ambiguous state, unreviewed build, combined DC/CA role, unsupported CA type, or unknown registry type/filter bits is `Unknown` and blocks changes. The command supports dedicated server CAs on builds 20348 and 26100; enterprise and standalone CA types remain distinct in evidence. Windows clients with no CA are not configured.

## Changes, restart and evidence

Every changed control uses the shared configuration runner: consent, typed before-state journal, a fresh observation after journaling, selected-field readback, preservation checks and final verification. Other CA identity, certificate, policy and service changes block continuation. The critical Active CA-A to CA-B race is tested through the legacy entry point as well as the dedicated engine.

`-AllowRestart` authorizes restarting an already-running CA only when its filter changes. A stopped/disabled CA is never started, and running dependent services block changes. Restart uses no `-Force`. Microsoft warns that auditing start/stop on a large CA database can make service operations slow; schedule an appropriate maintenance window. Administrative changes are not atomic with Windows registry/service operations, so avoid concurrent CA/GPO administration during this procedure.

The existing `configure` path delegates to the same guarded engine. Its existing confirmation or `-Auto` authorizes the historical filter-and-restart operation; no additional restart flag is imposed there. Failed or declined preceding audit prerequisites block its CA write. A dry run describes proposed operations without changing settings or restarting services.

`PolicyMatches` means the observed three settings match. It does not establish that a pre-existing filter is active in the current process. An unchanged filter is not restarted and activation stays `Unverified`, even if CertSvc is Running. After a changed filter, `RestartObservedAfterWrite` requires a newer process start plus unchanged identity/prerequisites; event generation still remains unverified. The report grants no usable Sigma-rule credit.

## Failure and recovery

A failed write, changed identity, readback discrepancy or failed restart produces a failure and a nonzero exit. Earlier verified prerequisites and a written filter can remain changed. The private journal retains exact earlier types/values/absence and CA identity; there is no automatic rollback.

If the filter was written but restart failed, the result records `RestartPending`. A later run finding 127 does not prove activation or silently retry a restart. Review the journal and current CA identity, effective auditing and service/dependency state before a deliberate maintenance restart. For an unchanged, still-running pending instance, [the explicit `adcs-resume` review and recovery command](adcs-restart-resume.md) provides a guarded plan, dry run and separately authorized restart. Any manual restoration must apply only to that same CA and restore only the specific recorded settings, preserving unrelated policy. Do not replay a journal onto another CA or override intervening administrator/GPO changes. Review both the individual results and the final snapshot after recovery.

## Disposable native validation

`tests/AdcsAuditing.Tests.ps1` exercises safe mocks, public CLI option guards and exact XML correlation. `tests/AdcsAuditing.Windows.Tests.ps1` additionally requires explicit `-AllowDisposableCA`, a GitHub-hosted Windows runner, a supported workgroup server and no existing CA. The workflow uses Server 2022/2025 and public CLI runs under PowerShell 5.1/7. Feature installation requiring reboot or unavailable native features fails the job instead of manufacturing acceptance.

Only that opt-in test provisions a uniquely named short-lived standalone root CA with private directories. It performs real public configuration/readback/idempotence tests, including malformed filter preservation and native no-auditing normalization. It submits the fixed public PKCS#10 fixture with a random request attribute and requires numeric COM disposition 5 (pending), a positive request ID, and exactly correlated local Security 4886/4889 XML. The corresponding CSR private key was discarded; no leaf certificate is approved, retrieved or installed. There is no domain publication, template change or auto-issuance switch. The script restores exact earlier audit/precedence policy, verifies all audit subcategories, and removes only its newly created CA, certificates, keys and feature additions. Cleanup failures fail the job and retain a private receipt.

After successful CA-resource removal and audit restoration, feature removal is requested only for additions made by the test. A successful Windows feature-removal result can require a reboot: its exact `RestartNeeded` value is recorded separately in a receipt and the CI log. Such pending removal relies on disposal of the GitHub-hosted VM after the job, not a verified complete OS feature rollback. An unsuccessful or unknown result, failed CA/key cleanup or failed audit restoration still fails the job. The test never restarts the runner, and this lifecycle allowance cannot turn a failed native test into success.

The native component XML and context/hashes are printed to the disposable CI log after matching. They demonstrate only that request on that host and run. The matcher supports reviewed event versions 0 and 1, retaining the additional version 1 fields and requiring the same provider, host, time, request ID, requester and nonce; 4889 also requires pending disposition 5. The version 1 XML fixtures preserve actual Server 2022 output from [the disposable diagnostic run](https://github.com/Yamato-Security/WELA/actions/runs/35503379380/job/106058973322). Unknown versions remain unverified. Enterprise template events, a combined DC/CA, Windows 11, forwarding, backend queries, volume, recovery across reboots and complete detection readiness remain separate lab acceptance. A checked-in test is not itself evidence that the native job passed; inspect the workflow result and recorded components.

Microsoft references: [standalone CA behavior and pending requests](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certification-authority-role), [CA installation parameters](https://learn.microsoft.com/en-us/powershell/module/adcsdeployment/install-adcscertificationauthority?view=windowsserver2025-ps), [Certification Services event fields](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn786423(v=ws.11)), [ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit), [GetRequestId](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-getrequestid), [pending disposition value](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/dbb2e78f-7630-4615-92c4-6734fccfc5a6), and [CA type values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/4fa5241c-d10e-4011-87e0-c74753d725a3).
