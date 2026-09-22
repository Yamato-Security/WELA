# Offline Intune audit policy export

`intune-export` creates reviewable Windows client Policy CSP artifacts from WELA's
shared advanced audit profiles. It runs offline under Windows PowerShell 5.1 or
PowerShell 7, including on a non-Windows authoring machine. It does not read or
change endpoint policy, authenticate to Graph, upload a profile or assign devices.
Sysmon and EMET are excluded.

```powershell
./WELA.ps1 intune-export -IntuneProfile wela-2.2.0 `
  -IntuneBuild 26100 -IntuneEdition Enterprise -IntuneOutputPath .\intune-wela-review

./WELA.ps1 intune-export -IntuneProfile microsoft-sct-win11-25h2 `
  -IntuneBuild 26200 -IntuneEdition Enterprise -IntuneOutputPath .\intune-sct-review

# Review the expansion beyond each one-bit minimum before selecting this option.
./WELA.ps1 intune-export -IntuneProfile microsoft-wef-reviewed-2026-09 `
  -IntuneBuild 26100 -IntuneEdition Enterprise -IntuneMinimumMode PromoteToBoth `
  -IntuneOutputPath .\intune-wef-expanded
```

Use `profiles` to list shared profile IDs. The target is an **operator declaration**:
client build **26100 (24H2)** or **26200 (25H2)**, with edition **Pro**, **Enterprise**,
**Education** or **IoTEnterprise**. Both the profile's client/build scope and the
exporter's reviewed CSP scope must match. Unknown builds/editions and server,
DC or AD CS profiles are rejected. Home is not supported by these CSP settings.
This is CSP applicability, not certification that a source benchmark covers every
declared edition; for example, the reviewed CIS source is Windows 11 Enterprise.
Source versions and limitations remain in the manifest.

`-IncludeOptional` selects optional rows using their shared profile's exact-mask
semantics. Other commands reject `-Intune*` options before dispatch. This command
rejects configuration, consent, live role/build overrides and unrelated export
options; use the dedicated parameters above. No elevation or tenant access is
needed to generate files.

| Shared mode | Offline CSP treatment |
| --- | --- |
| `exact` | Integer 0, 1, 2 or 3 exactly as specified; this can disable existing bits. |
| `minimum`, mask 0 | Preserve; no payload setting. |
| `minimum`, mask 3 | Integer 3; equivalent for the native two-bit mask. |
| `minimum`, mask 1 or 2 | Default `Reject`: review-only bundle and exit 1. Explicit `PromoteToBoth`: integer 3 with expansion recorded for every affected row. |
| Selected `optional` | Exact integer mask. |
| Unselected `optional`, `unchanged`, `not-configured`, `not-applicable` | Retained as separate manifest rows; no payload and no Delete. |

The CSP contract is **0=None, 1=Success, 2=Failure, 3=Success+Failure**, data type
**Integer**, not String/XML, Boolean or registry binary data. Microsoft's DDF marks
these policies `LastWrite`. A static integer cannot implement “enable Success but
preserve whichever Failure bit each device already has.” `PromoteToBoth` sets both
bits and can increase event volume; it is not a live merge or exact reproduction
of the source minimum. Some subcategories produce only one outcome despite
accepting the full mask; exporting a bit is not event-generation evidence.

Documentary default profiles are blocked. No-setting profiles produce review-only
output rather than an unrelated precedence-only policy. A blocked bundle retains
all 59 rows and reasons, but contains neither deployment JSON nor settings CSV.
Do not manually extract candidate rows from it as though they formed a complete
policy. Correct the blockers and export to a new directory.

## Artifacts and provenance

The output must be a **new local directory under an existing parent**. Existing
files/directories, UNC/device paths, drive-relative paths, wildcard/parent-traversal
paths and symlink/reparse ancestors are refused; on Windows use a fixed local
drive. Writes use `CreateNew` and verify bytes after writing. A failure can leave
partial files for review. **`SHA256SUMS.json` is written last**; without it, the
bundle is incomplete. Hashes identify bytes and detect changes, not source trust.

| File | Purpose |
| --- | --- |
| `manifest.json` | All 59 shared rows, target declaration, omission/expansion reasons, candidate values, prerequisites, source/profile/mapping fingerprints and unverified deployment state. |
| `oma-settings.csv` | Manual-entry/review list: Name, Description, case-sensitive OMA-URI, Integer data type and Value. **Not a portal-importable CSV profile.** |
| `graph-body.json` | Offline Graph v1.0 `windows10CustomConfiguration` body, with typed `omaSettingInteger` rows. No tenant ID, object ID, credentials or assignments. **Not Settings Catalog import JSON.** |
| `README.txt` | Standalone review/deployment notes, included in release-generated bundles. |
| `SHA256SUMS.json` | Completion status and SHA-256/byte length for each preceding artifact. |

[`config/intune_audit_csp.json`](../config/intune_audit_csp.json) pins the official
[February 2026 DDF package](https://learn.microsoft.com/en-us/windows/client-management/mdm/configuration-service-provider-ddf)
and both exact DDF paths/hashes. It contains 59 explicit GUID-to-URI mappings;
runtime names are not guessed by concatenation. This includes the non-obvious
`DetailedTracking_AuditPNPActivity`, `DetailedTracking_AuditTokenRightAdjusted` and
`PolicyChange_AuditPolicyChange` spellings. The DDF's literal GP label typo
“Distributio Group Management” is preserved as provenance, without changing its
correct URI. Only the 49 client-applicable catalog rows can become client payload
settings, further restricted by the selected profile. Source CSP defaults are
documentary metadata, never assumed endpoint values.

## Precedence, conflicts and deployment evidence

Every nonempty deployment payload includes a separate prerequisite Integer **1**:
`./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/Audit_ForceAuditPolicySubcategorySettingsToOverrideAuditPolicyCategorySettings`.
This controls `SCENoApplyLegacyAuditPolicy`. Microsoft documents this CSP from
build 26100 and its backport to 22621.5126. Earlier Windows 11 releases may support
the audit subcategory CSPs while lacking this prerequisite CSP; this initial
exporter deliberately restricts target builds instead of silently omitting it.
The setting is identified separately from source-profile subcategories.
[Microsoft precedence CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-localpoliciessecurityoptions#audit_forceauditpolicysubcategorysettingstooverrideauditpolicycategorysettings)

Audit subcategory precedence does not settle MDM versus GPO ownership. WELA does
not emit `MDMWinsOverGP`. Review overlapping security baselines, Settings Catalog,
custom policies, GPO and scripts before deployment. Microsoft's conflict control
has a distinct scope; `LastWrite` is not proof that a particular competing profile
will win. No policy ordering, tenant conflict check or atomic application is
claimed. [Microsoft conflict control](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-controlpolicyconflict)

An authorized operator can enter the CSV rows in a Windows custom profile or
review the Graph body using their organization's deployment process. Intune's
custom-profile documentation requires Add, Replace and Get support; all emitted
nodes provide these operations. An export does not demonstrate the tenant will
accept them. The artifact does not enforce its edition/build declaration through
assignments or filters; scope a matching enrolled pilot explicitly.
[Intune custom settings](https://learn.microsoft.com/en-us/intune/device-configuration/templates/configure-custom-settings-windows),
[Graph custom configuration](https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-windows10customconfiguration-create?view=graph-rest-1.0),
[Graph integer setting](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-omasettinginteger?view=graph-rest-1.0)

Retain pre-deployment authoritative policy evidence. After a separately authorized
pilot, inspect per-setting Intune status and MDM diagnostics, verify the registry
precedence value and actual subcategory masks using WELA, test ordinary policy
sync/GPO coexistence, and retain benign event/collection evidence. Omitting a
setting from a later export is not a Delete and does not undo an older assignment.
Unassignment/deletion may restore defaults or another policy rather than the prior
local value; recovery requires review of the current policy owners. No automatic
rollback is generated. SACLs, process command-line payloads, channels, log sizes,
retention and forwarding are separate workflows.

Tests cross-check mappings against extracted DDF facts, validate all mask/mode
cases, exercise the public exporter/CLI and verify file fingerprints and refusal
paths on PowerShell 5.1/7. Native/HTTP adapters are forbidden in offline fixtures.
CI does not enroll a client, upload anything or mutate Windows. Intune acceptance,
pilot assignment, effective masks after sync, conflicts, recovery and event
generation remain deployment evidence needed before fully closing issue #1.
No compliance or Sigma uplift is inferred from export success.
+### Issue 1 coverage

The Intune export emits a versioned offline audit payload for a declared Windows build and profile, preserving omission and minimum semantics while hashing source mappings. File creation does not claim tenant assignment, policy acceptance, resultant settings, or event readiness.
