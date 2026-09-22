# Audit identifiers and EventID mapping review

`Token Right Adjusted Events` now uses `0CCE924A-69AE-11D9-BED3-505054503030` in the legacy baseline catalog, matching the versioned audit catalog. RPC keeps `0CCE922E-69AE-11D9-BED3-505054503030`. This fixes legacy ASD/Microsoft assessments that previously displayed RPC state for token auditing. Recommendations and enablement masks are unchanged.

Every baseline load checks canonical name/GUID pairs and rejects duplicate legacy identifiers. Only three explicit spelling aliases are accepted: `Non-Sensitive Privilege Use`, `User / Device Claims`, and `Central Policy Staging`. They map to the existing canonical names; no fuzzy matching or arbitrary GUID aliases are allowed.

Review the bundled EventID candidates without reading or changing Windows:

```powershell
./scripts/Review-AuditCatalog.ps1 -ResultsPath mapping-review.json
```

The export fingerprints the mapping file, lists candidates and reasons per EventID, and separates blank category headings. Missing mappings or candidates with only a category GUID are unknown. Multiple subcategories, unresolved object types, outcomes and role context remain conditional. `DetectionReady` is always false: an identifier review cannot verify a detection. This helper does not replace full rule eligibility or establish the complete Boolean/field requirements of a Sigma rule.

The bundled CSV remains a historical candidate map, not a universally valid event-generation contract. For example, 4703 appears against both Token Right Adjusted and Authorization Policy Change. Microsoft's [Token Right Adjusted page](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-token-right-adjusted) lists it, while the [4703 event page](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4703) names Authorization Policy Change. WELA retains the conflict rather than inventing a build-independent resolution. Microsoft also states that Token Right Adjusted has no Failure events; setting a Failure mask is not proof of Failure records.

Fixtures check malformed/duplicate identifiers, unknown events, ambiguous 4703/object mappings, and independent RPC/token state through all four legacy baseline renderers. Windows CI runs [`auditpol /list /subcategory:* /v`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-list) and native policy queries under Windows PowerShell 5.1/PowerShell 7. These checks validate identifiers/readback, not generated event XML. Build-specific client, member-server, DC and CA event/outcome validation remains separate acceptance work for issue #380. Native Windows functionality only; Sysmon is out of scope.

A separate [native4703 attribution fixture](native-token-right-attribution.md) compares the two selected masks on disposable standalone Server2022/2025 hosts with actual fixed privilege-adjustment XML. It retains all other audit masks and records the build/UBR and provider schema. This bounded generation evidence leaves historical candidates conditional and does not grant detection readiness.
