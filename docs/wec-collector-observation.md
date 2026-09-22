# Native collector subscription observations

The existing `wec-collector` Audit and Plan commands now enumerate subscription names through the local Windows Event Collector API and read selected XML through the shared bounded Unicode reader. This avoids treating PowerShell console output, including a BOM-only empty result, as subscription identity. Non-ASCII descriptions and XPath literals remain intact in the report.

```powershell
.\WELA.ps1 wec-collector -WefAction Audit `
  -WefConfigPath C:\Reviewed\collector.json -ResultsPath C:\Evidence\collector-audit.json
.\WELA.ps1 wec-collector -WefAction Plan `
  -WefConfigPath C:\Reviewed\collector.json -ResultsPath C:\Evidence\collector-plan.json
```

Use the explicit collector configuration described in [WEF deployment](wef-deployment.md). These commands observe the selected local subscriptions and prerequisites. They do not create, save, enable or delete subscriptions. Existing Configure remains create-only and retains its domain, listener, ingress and hardening prerequisites.

A successful complete enumeration can establish `ObservedSubscription.Exists: false`; its `ObservedEnabled` remains null. An enumeration error, cap, duplicate/invalid native name, vanished or unreadable selected definition, mismatched XML identity or unsupported authorization remains unknown, with `ObservationError` and an `Unknown` control. Failed observations never authorize creation. A valid disabled definition is reported as disabled even when the requested XML says enabled. A readable difference requires manual review rather than a replacement.

Enumeration preserves exact native UTF-16 names, including Unicode and whitespace; it does not trim names or parse localized command output. It is limited to 4,096 names, 1,023 UTF-16 characters per name and 1,048,576 total characters including terminators. Exceeding a bound fails the observation instead of returning a partial list. Selected subscription IDs continue to use the existing supported ASCII ID syntax, and native XML reads retain their ten-MiB and thirty-second bounds. Native API errors are preserved as failures. The loaded enumeration helper is bound to its implementation bytes.

Enumeration and XML readback are sequential observations, not a transaction or protection against another administrator. A disappearing subscription is unknown for that observation; retry with a fresh audit. A complete configuration match still does not establish source identity, effective source access, runtime health, event arrival, bookmark continuity or Sigma coverage. Collector-local channel observations describe only the collector.

The disposable native suite exercises the actual public commands on Server 2022/2025 with Windows PowerShell 5.1 and PowerShell 7. It uses one uniquely owned disabled subscription with Unicode description and XPath, verifies absence, exact observation, requested/observed state separation, changed-description review and authorization-mismatch uncertainty, then removes only the owned subscription and restores original service startup/state. It preserves the destination channel and original subscription inventory. The real standalone fixture remains `Incomplete` with exit 1 for domain deployment prerequisites; those checks are neither mocked nor counted as domain or forwarding proof. Native name-buffer, cap, duplicate and read-failure regressions supplement that Windows acceptance.

Microsoft references: [subscription enumeration](https://learn.microsoft.com/en-us/windows/win32/api/evcoll/nf-evcoll-ecenumnextsubscription), [enumeration handles](https://learn.microsoft.com/en-us/windows/win32/api/evcoll/nf-evcoll-ecopensubscriptionenum), and [wecutil XML/read-only commands](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wecutil).
