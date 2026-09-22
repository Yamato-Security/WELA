# Transparent native audit scores

The read-only `score` command reports two independent measures: selected advanced audit-profile configuration compliance and severity-weighted, evidence-qualified native rule readiness. It does not assign an overall security grade. Sysmon is excluded from the readiness measure through the shared native eligibility classifier.

```powershell
# Observe the actual local Windows host against an explicit built-in profile.
./WELA.ps1 score -ScoreProfile wela-2.2.0 `
  -ResultsPath .\score.json -HtmlPath .\score.html

# Offline declared scenario, on any platform. No local policy is observed.
./WELA.ps1 score -ScoreProfile wela-2.2.0 -Role Client -Build 26100 `
  -ResultsPath .\client-scenario.json -HtmlPath .\client-scenario.html

# Assess independently collected complete-rule evidence in its recorded context.
./WELA.ps1 score -ScoreProfile wela-2.2.0 -Role MemberServer -Build 20348 `
  -ScoreEvidencePath .\reviewed-lab\evidence.json -HtmlPath .\lab-readiness.html
```

Use `profiles` to list supported built-in IDs and applicability. Specify both Role and Build for a declared offline scenario, or omit both to detect the real Windows host. Supplying Role/Build always selects offline behavior, including on Windows. Offline configuration stays Unknown without credit. Actual observations require a complete, consistent native host context; an unavailable effective-policy reader is reported separately from a known mismatch. Read timestamps and host metadata in the report; a later GPO/MDM refresh can change the settings. No policy is applied, refreshed, cleared or restored by scoring.

`-ScoreProfile` is required. `-IncludeOptional` selects optional profile controls. Reference-only documentary Windows defaults are not deployable recommendations and are rejected as compliance targets. Custom profile files and custom rule corpora are outside this initial score command. Its dedicated options cannot be used with configuration commands; output files must be new, distinct filesystem paths under existing directories. Relative output paths use PowerShell's current location, including after `Push-Location`; Windows case-variant collisions and non-filesystem providers are rejected before either output is written.

## Configuration compliance

Each included advanced audit-policy subcategory has weight 1. Audit precedence (`SCENoApplyLegacyAuditPolicy`, DWORD 1) adds one control when there is a substantive selected audit requirement. The numerator is the number of compliant controls; the denominator includes compliant, drifted and unknown selected controls.

| Profile entry | Treatment |
| --- | --- |
| Exact mask 0, 1, 2, 3 | Current effective mask must equal the requirement |
| Minimum mask 1, 2, 3 | Current mask must contain all required bits; extra bits are accepted |
| Minimum mask 0 | No constraint; excluded |
| Optional | Excluded unless selected; selected mask is exact |
| Unchanged / Not Configured / Not applicable | Excluded, with the reason retained |
| Unknown current mask or mistyped precedence | Included with zero credit and an Unknown state |

For example, two compliant audit controls plus unknown precedence produce 2/3, or 66.67%. An all-preserved/minimum-zero profile has no substantive constraints, so precedence is also excluded and the percentage is N/A. A missing precedence value is a known mismatch; an unreadable or incorrectly typed value remains Unknown.

This percentage covers advanced audit masks and precedence only. It does not score channel enablement, event payload capture, object/AD/WMI SACLs, provider or service activation, AD CS filters, log sizes, retention, access permissions, forwarding, event generation or backend detection. Per-control source IDs and unscored prerequisites remain visible. A 100% configuration result cannot establish that a Sigma rule works.

## Evidence-qualified rule readiness

The command freshly invokes `Get-WelaRuleEligibility` against the shipped pinned corpus and mapping. It does not trust an uploaded score summary or use enabled settings as a Ready result. Identical duplicate rule IDs are counted once by the shared classifier; conflicting metadata is rejected. Severity metadata is bound to the exact corpus bytes assessed, and changes to the corpus, mapping or pin manifest during scoring cause failure.

| Rule severity | Weight |
| --- | ---: |
| Critical | 20 |
| High | 15 |
| Medium | 10 |
| Low | 5 |
| Informational | 1 |
| Missing or unknown | 1, visibly identified |

The denominator is the sum of weights for applicable unique native candidates. Conditional, Blocked and unknown candidates remain included. Only evidence-qualified Ready rules earn their weight in the numerator. Explicit NotApplicable and Excluded rules—including Sysmon sources—are removed from the denominator and retained in the full list. Zero applicable candidates produces N/A, not 100%.

For example, one Ready critical rule, one Conditional high rule and one Blocked low rule produce 20/(20+15+5) = 50%. This is a severity-weighted readiness percentage, distinct from the shared classifier's unweighted rule counts and percentages, which remain in JSON. The weights are transparent review priorities, not probabilities, attack coverage or an independent estimate of risk.

Without a complete supported evidence bundle, readiness earns zero credit. This indicates that usability has not been demonstrated by the supported evidence contract; it does not prove the enabled logs have no detection value. See [native rule eligibility](native-rule-eligibility.md) for the required original rule, complete normalization review, native configuration/event, ingestion and query artifacts. Unsupported rule logic and incomplete evidence remain conditional. Scoring never creates or executes a detection scenario, contacts a backend, translates a query or manufactures results.

Ready results apply to each artifact's original host, role, patch, backend/version and time. Those contexts can differ across rules and from the machine running the report. The per-rule evidence time, context, reasons and references are preserved; aggregating them does not establish present readiness on a single deployment.

## Reports, versioning and tests

JSON retains the definition/version/hash, profile plan and source provenance, actual or declared observation basis, both measures and every underlying eligibility result. The self-contained HTML has two score cards, visible numerators/denominators, unknown/exclusion counts, a configuration table and a rule table with evidence context/time. The observed computer, observation time, detailed host context and policy-read diagnostic are visible separately from historical rule evidence. Arbitrary text is HTML-encoded; no external scripts or assets are loaded. Neither report overwrites existing files. If one output fails after the other has been written, preserve the completed artifact and choose new destinations when retrying.

Version 1.0.0 is defined in `config/audit_scoring.json` as `native-audit-score-v1`. Changing weights requires a reviewed definition-version change, rather than silently moving the denominator. Exact profile and corpus fingerprints let a reviewer identify what was assessed. The profile hash must match before and after planning and the plan's returned hash; observed source changes abort reporting. Hashes bind recorded content, not the trustworthiness of a malicious evidence author. Letter grades and a combined security score are deliberately not defined by this first implementation of issue #10.

Tests cover exact/minimum mask truth tables, optional/role omissions, unknown and empty denominators, severity weights, exclusions/unique IDs, evidence-context preservation, source changes, output collisions, HTML encoding and public command isolation. Windows Server 2022/2025 PowerShell 5.1/7 tests read real policy and verify that native masks/precedence remain unchanged. Synthetic Ready rows test arithmetic only. No Windows 11/DC/AD CS deployment or backend query evidence is claimed by those tests.
+### Issue 10 coverage

Audit scoring uses weighted rule metadata and reports numerator, denominator, exclusions, and conditional evidence. A score summarizes reviewed eligibility states; it does not prove event generation, forwarding, or detection.
