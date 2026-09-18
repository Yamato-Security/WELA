# Native AppLocker readiness

`applocker-readiness` reports local and GP effective policy XML, each of the five rule collections, enforcement modes, rule counts, Application Identity (`AppIDSvc`) state/start mode and relevant AppLocker channel observations. A host with enabled channels but no rules reports `MissingGpPolicy`. Stopped/disabled services, missing channels, unavailable cmdlets and read errors remain explicit. `NotConfigured` with rules is treated as potential enforcement, never as disabled.

```powershell
./WELA.ps1 applocker-readiness -ResultsPath applocker.json
./WELA.ps1 applocker-readiness -AppLockerAction Plan -AppLockerPolicyPath operator-audit.xml -ResultsPath plan.json
./WELA.ps1 applocker-readiness -AppLockerAction Import -AppLockerPolicyPath operator-audit.xml -DryRun
./WELA.ps1 applocker-readiness -AppLockerAction Import -AppLockerPolicyPath operator-audit.xml -BackupPath C:\WelaBackups\applocker-001 -ResultsPath imported.json
```

The default is read-only Audit. Windows 11 clients and member servers running Server 2016 or later are candidates; availability is checked through the actual native cmdlets and service. Edition names alone do not establish capability. Import requires a 64-bit elevated session. Ordinary `configure` does not invoke this workflow. No service, channel, application control enforcement or forwarding settings are automatically changed.

## Scope and import safeguards

Import accepts an **operator-supplied** native XML policy. Every included collection must explicitly be AuditOnly and contain rules. XML DTDs, namespaces, unknown collection types, duplicate IDs and policy extensions are rejected. The native `Test-AppLockerPolicy` cmdlet validates the prepared XML before it can be installed; it does not execute the test file. There are no generated blanket allow rules or default policy assumptions.

Import only initializes an empty local/GP policy, or verifies an identical previously imported policy. Existing configured collections, existing enforcement (including NotConfigured collections with rules), unreadable policy, domain membership, observed enrollment/provider entries or unknown management state block import. Use the organization's policy authority to manage those hosts. The workflow uses `Set-AppLockerPolicy -Merge`, retains original policy XML in the recovery journal, rechecks state before writing, and verifies local collection content again after writing and at completion. It does not replace an existing policy. An import failure is reported with a nonzero exit code. Dry-run makes no policy or recovery-file changes.

Microsoft's [Get-AppLockerPolicy documentation](https://learn.microsoft.com/en-us/powershell/module/applocker/get-applockerpolicy) limits that cmdlet to GP policies: **CSP policies are invisible**. Enrollment/provider observations are conservative blockers, not proof that CSP policy is absent. `CspPolicyState=Unknown` remains in every assessment; review other management mechanisms before choosing local import. The [merge semantics](https://learn.microsoft.com/en-us/powershell/module/applocker/set-applockerpolicy) preserve existing enforcement mode. Concurrent policy administration is not an atomic transaction with this workflow; keep the deployment window isolated and review the final readback. No automatic rollback overwrites newer policy.

Recovery: keep the backup directory outside temporary folders. `before.jsonl` contains the original local and GP policy XML, service/channel/management observations and desired policy. The prepared imported XML is retained as `appLocker-audit-import.xml`. Compare them with a fresh audit before recovery; use the existing policy authority or Local Security Policy to remove only the policy created by this run. Do not blindly restore stale effective domain policy or remove someone else's new rules. Use an isolated machine snapshot for integration tests.

## What readiness means

`Conditional` means GP rules, a running service and enabled channels were observed. All collections still report `GenerationReadiness=Unverified` and zero usable-rule credit. A policy can omit rule collections, contain rules that do not match the relevant user/application, or be superseded later. Missing GP rules do not prove no CSP rules exist. A successful import verifies local policy content only; it does not start the service, validate an actual executable/script event or verify collector ingestion.

[Microsoft WEF guidance](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection) recommends at least an audit-only policy. See Microsoft's [audit-only configuration](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/configure-an-applocker-policy-for-audit-only), [requirements](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/requirements-to-use-applocker) and [rule enforcement behavior](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/working-with-applocker-rules). Native Windows functionality only; Sysmon is out of scope.

Before closing issue #381, on an isolated patched Windows 11/member-server snapshot, export policy/service/channel state, import a reviewed audit-only policy, explicitly configure required service prerequisites, run a benign executable and script, and match the expected AppLocker event XML to their paths/user/rule collection. Confirm an enforced policy stays unchanged when this importer refuses it. Repeat for managed hosts and validate forwarding where required. CI only uses mocked mutations and actual read-only native policy/schema observations; it does not establish event generation or production deployment safety.
