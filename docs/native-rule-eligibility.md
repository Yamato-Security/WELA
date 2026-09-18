# Native rule eligibility and imported lab evidence

`rule-eligibility` is a read-only assessment of the bundled rule metadata and optional operator-supplied lab artifacts. It does not configure Windows, generate events, run queries, contact collectors or execute imported files. Sysmon and explicitly identified external-product sources are excluded.

```powershell
./WELA.ps1 rule-eligibility -ResultsPath eligibility.json -HtmlPath eligibility.html
./WELA.ps1 rule-eligibility -Role ADCS -Build 26100 -ResultsPath ca-candidates.json
./WELA.ps1 rule-eligibility -RuleEvidencePath C:\Lab\reviewed\evidence.json -ResultsPath reviewed.json
```

Without imported evidence, **Ready is zero**. This means detection readiness has not been demonstrated; it does not mean the configured logging is useless. The shipped `security_rules.json` contains extracted Hayabusa metadata, including candidate channels, EventIDs and subcategories. It omits full detection expressions and required fields. It is not the entire upstream Sigma corpus. Generic process-creation rules are retained as candidates, but mapping them to 4688 does not establish that Windows supplies every required field.

The manifest records the exact corpus and EventID-mapping SHA256 values and counts. Historic upstream commits that were not recorded remain null. Future automated rule updates record the Hayabusa and generator commit IDs. `tools/update_rule_manifest.py` regenerates hashes; use its commit arguments only for the actual inputs that produced those bytes. Custom extracted metadata and a matching reviewed manifest can be supplied with `-RuleCorpusPath` and `-RuleManifestPath`. A hash identifies content; it does not authenticate its origin.

## Reading the results

| State | Meaning |
| --- | --- |
| Ready | All supported checks pass against imported, reviewed lab artifacts. Applies only to the recorded computer, role, build, patch, backend/version and test time. |
| Conditional | Missing/unknown metadata or prerequisites, unsupported rule logic, or rejected/incomplete/stale evidence. |
| Blocked | Every observed candidate source for the rule is explicitly disabled or absent. No missing observation is interpreted as disabled. |
| NotApplicable | All unambiguous, canonical Security event sources belong to other roles than the explicitly selected role. |
| Excluded | An explicit Sysmon or identified external-product source. Its ID and exclusion reason remain in the output. |

Every unique rule has reasons and a metadata hash. `ordered-json-html-escaped-utf8-sha256-v1` hashes compact JSON with the fixed field order `id,title,level,category,service,channel,event_ids,subcategory_guids,description,tags`, explicit HTML escaping and UTF-8 without a BOM; this keeps per-rule identities stable across PowerShell 5.1 and 7. Corpus, mapping and imported-artifact hashes always cover the exact file bytes. Git attributes preserve LF checkouts for the shipped pinned inputs, without normalizing imported evidence. `PolicyPrerequisites` inventories the catalog's requirements; it is not a separate failed-check verdict. Identical duplicate IDs count once; conflicting duplicate IDs are rejected. The report provides input record count, unique rule count, native candidate count, role-applicable count and exclusion groups. It reports **Ready / native candidates**, **Ready / applicable candidates**, and **Ready / full unique corpus** separately. Empty denominators produce null percentages. Unknown and incomplete native candidates remain in the denominator, including generic categories lacking a verified adapter. These denominators therefore differ from the earlier standalone comparison report's explicitly narrower modeling boundary; do not compare their percentages without reconciling scope and corpus versions.

Category-only GUIDs, blank EventID rows and ambiguous mappings cannot establish subcategory/outcome readiness. In particular, the mapping lists both Token Right Adjusted Events and Authorization Policy Change for 4703; the importer does not arbitrarily choose one. Directory-service and certificate-template change events must be assessed on their source DC, not credited automatically to a member-server CA.

`audit-settings -Baseline` still reports actual configuration. Its `UsableRules.csv`, headline percentage, JSON/HTML and current/ideal Navigator outputs no longer promote rules solely from an enabled policy or channel. `RuleEligibility.csv` records all states/reasons. `ConfigurationEstimate` is retained separately and is not detection readiness. Without lab artifacts those outputs contain no Ready rules. Imported historical Ready results are deliberately reviewed in the separate command; they are never silently applied to the currently audited host. The familiar `UnusableRules.csv` includes unconfirmed rules, not only proven failures.

## Evidence trust and supported parsing boundary

The operator supplies trusted lab records. WELA verifies file hashes, schema consistency, source-event identity, supported rule logic, required field presence, timing, policy outcome and cross-references. It **does not independently authenticate who collected the artifacts, prove a reviewer's assertions, or run the backend**. A matching hash and `matched: true` alone are insufficient: all nine artifacts and their links must pass. A coherent imported record is still evidence from that recorded test, not a production SLA, broad attack validation or a guarantee after policy refresh.

Version 1 supports `security-single-event-exact-v1`: one native Security event from `Microsoft-Windows-Security-Auditing`, one unambiguous canonical audit mapping, and full normalized rule JSON whose detection consists solely of a nonempty `selection` mapping with scalar exact values and `condition: selection`. Product must be Windows; a service, if present, must be `security`; the only supported generic category is `process_creation` with 4688. Filters, wildcards, lists, field modifiers, correlation, extra detection clauses, unknown source prerequisites, unsupported/deprecated rules, other provider adapters and SACL-dependent rules remain Conditional. Unsupported syntax is never partially evaluated. Adding further adapters requires reviewed semantics and regression fixtures.

The normalized full rule is an operator-reviewed JSON representation of the original source rule. Both artifacts are hashed and linked by an explicit normalization review. The original source is retained as evidence, never executed or interpreted by a general YAML loader. This is a human attestation boundary; WELA cannot prove the normalization faithfully represents arbitrary YAML. A false review can invalidate the result.

Field mappings are limited to `System.EventID` and same-named `EventData` fields, plus reviewed 4688 aliases: `Image` → `NewProcessName`, `ParentImage` → `ParentProcessName`, `ProcessId` → `NewProcessId`, and `ParentProcessId` → `ProcessId`. The original event and ingested normalized values must match the exact rule selection. The importer checks 4688 event versions and its documented native field set; it does not invent hashes, original filenames or other rich telemetry. A required empty command line fails, and nonempty command-line evidence also requires a recorded DWORD command-line capture policy. See [Microsoft's 4688 schema](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688).

## Bundle and artifact contract

The evidence bundle has `schemaVersion: 1`, `kind: WelaNativeRuleEvidence`, and a `records` array. Each record contains:

- `id`, `metadataSha256` from the per-rule report, and the exact `corpusSha256` / `mappingSha256`.
- `adapter: security-single-event-exact-v1` and `fieldMappings`, for example `{"EventID":"System.EventID","Image":"EventData.NewProcessName"}`.
- `artifacts`: the nine names below, each containing a relative local `path` and exact file `sha256`.

| Artifact | Required contents |
| --- | --- |
| `sourceRule` | Complete original rule artifact retained for review/provenance. |
| `normalizedRule` | Complete reviewed JSON rule: `id`, `logsource`, and supported `detection` described above. |
| `review` | `ruleId`, `reviewer`, `reviewedAtUtc`, both `sourceRuleSha256` and `normalizedRuleSha256`, and exact statement `Complete rule normalization reviewed; no detection logic omitted.` |
| `beforeState` | `context`, `capturedAtUtc`, and `auditPolicies` containing the canonical GUID's observed mask before the test. |
| `afterState` | Same context, capture time and policy map; `auditPrecedence: {kind: DWord, value: 1}`, boolean `securityChannelEnabled`; for required 4688 command lines, `commandLineCapture: {kind: DWord, value: 1}`. |
| `eventXml` | One complete native Event XML with provider, EventID, version, keywords, UTC time, record ID, channel, computer and named EventData. DTDs, external entities, duplicate fields and unsupported payloads are refused. |
| `ingestion` | `eventSha256`, source `computer`, `channel`, `eventId`, `recordId`, `receivedAtUtc`, backend identity/version and `normalizedFields` for every selector. |
| `query` | Exact translated query text used by the backend test; never run by WELA. |
| `queryResult` | `ruleSha256` for normalized rule, `querySha256`, `eventSha256`, `backend`, `backendVersion`, `executedAtUtc`, boolean `matched: true`, numeric `exitCode: 0`. |

Each state artifact's `context` must contain `computer`, `role`, integer `build`, nonempty `patch`, boolean `domainJoined`, `installedRoles` array, `backend` and `backendVersion`. Before/after identity must agree. All timestamps use UTC `Z`. Before-state precedes the event; event precedes after-state and ingestion; ingestion precedes query execution; review follows query execution. Evidence beginning more than 30 days before assessment, or future-dated/inconsistent evidence, stays Conditional. This fixed freshness limit is an assessment bound, not a claim that policy persists for 30 days. Record exact software versions, snapshots, test actions and capture procedure in the source lab notes.

Only relative files inside the bundle directory are read. Traversal, UNC paths, linked ancestors/files, empty files and artifacts over 4 MiB are rejected; bundle/corpus inputs are limited to 16 MiB. JSON property collisions are rejected in evidence. These checks are local observations, not an atomic defense against an administrator replacing directories during review; keep the evidence directory controlled and immutable during assessment.

`tests/RuleEligibility.Tests.ps1` builds a complete **synthetic** fixture and adversarial variants that illustrate this contract. It is not evidence of a real Windows event, source-policy change, ingestion or backend execution and must not be reused as such.

## Lab completion

Use separate Windows 11, member-server, DC and member-server CA snapshots. Record build/patch, domain membership, roles, corpus/mapping hashes and backend version. Capture before state, apply an approved source profile, generate a benign operation corresponding to one explicitly selected full rule, save native XML, then capture after state. Confirm field normalization and source identity at the collector/backend, execute the exact translated query, retain its match and independently review the normalization. SACL-dependent rules require additional reviewed adapters; a file/AD/WMI policy toggle alone never closes that gap. Measure event volume, loss/backlog and overhead separately and preserve those records; this importer does not infer EPS or storage capacity.

Hosted CI uses synthetic fixtures and read-only Windows observations. It supplies no clean-image before/after matrix, genuine backend-query/ingestion result or end-to-end detection claim. Issue #387 remains open for those acceptance tests and for additional rule/parser adapters.
