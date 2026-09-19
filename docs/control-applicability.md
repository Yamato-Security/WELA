# Historical controls and Windows default evidence

These read-only commands address issue #385. Sysmon is out of scope. They do not
install optional features, modify registry/audit policy or grant Sigma eligibility.

```powershell
./WELA.ps1 control-applicability -ResultsPath applicability.json
./WELA.ps1 default-evidence -ResultsPath observed.json
./WELA.ps1 default-evidence -DefaultEvidenceAction Compare -DefaultEvidencePath reviewed-clean-install.json -ResultsPath comparison.json
```

Run in 64-bit PowerShell. Complete native role/feature and effective audit-policy
reads can require elevation. Context is always observed locally; `-Role`/`-Build`
overrides and configuration options are rejected. A partial capture preserves
successful observations and reports failed ones as Unknown, returning a nonzero
exit code. Failed reference qualification also returns nonzero.

## Application Guard

The versioned `config/control_applicability.json` retains CIS Windows 11 Enterprise
v4.0.0 control 18.10.44.1 and its historical `AuditApplicationGuard=1` requirement.
It records a Windows 11 minimum build (22000), maximum pre-removal build (26099),
reviewed releases (22000/22621/22631), editions, optional feature and source/removal
metadata. It is an initial historical-control catalog; existing advanced audit
profiles and SMB/provider commands keep their own applicability checks.

Microsoft removed Application Guard starting Windows 11 24H2 (build 26100).
24H2/25H2 and later client builds therefore report NotApplicable without querying
or attempting to reinstall it, even if stale registry or feature metadata remains.
Servers, including DC/AD CS, are outside this historical client source scope.
On reviewed older builds, an enabled `Windows-Defender-ApplicationGuard` feature
allows read-only auditing of the typed registry value. Disabled/absent features
are NotApplicable; unreviewed builds/editions, inaccessible or pending feature
states remain Unknown. The original source requirement is always retained.
There is no automatic historical remediation, and an enabled feature is not proof
of application readiness or event generation.

## Default column correction

The existing baseline JSON contains historical default strings without sufficient
build/patch/role provenance. Public audit assessments now show `DefaultSetting`
as Unknown and retain those strings separately as `LegacyDefaultHint` in CSV,
JSON, HTML and GUI output. `DefaultEvidence` explains the distinction. Standard
output likewise explains why the default is Unknown. Recommendations/current
observations are unchanged. The versioned `windows-defaults-*` advanced-policy
profiles remain explicitly documentary reference profiles, not clean-machine
snapshots. This PR does not replace those reference profiles or fabricate lab data.

To use a reviewed scenario snapshot, run the dedicated `default-evidence Compare`
command. It does not silently rewrite normal audit columns or baseline metadata.
Use a separate `ResultsPath`: a comparison refuses an output path that resolves
to its `DefaultEvidencePath`, preserving the reviewed input artifact.
The comparison reports a per-control default/reference and match/difference only
when reference provenance and exact context qualify; other defaults stay Unknown.
Channel observations retain individual channel names and states; registry records
retain each path, type, value and absence. They are not collapsed to assumed defaults.

## Capturing and reviewing reference scenarios

Capture records the exact Windows build and UBR patch, edition, localized OS
architecture and independently observed `Win32_Processor.Architecture` platform
code (x64 = 9, ARM64 = 12),
product type, domain role, join state/domain, and a complete installed feature/role
inventory. A CA role or DC promotion creates a distinct scenario rather than a
universal "Server default". It includes current typed registry state, native channel
metadata and all 59 canonical advanced audit subcategories. Individual failures
remain Unknown. It also records source versions and SHA-256 fingerprints for the
baseline/profile/applicability catalogs, this collector script and its native
reader helpers (`Configuration.ps1`, `NativeProviders.psm1`, `AuditProfiles.psm1`);
these inputs use LF checkouts so byte fingerprints are portable. Missing,
unsupported or inconsistent processor codes leave context Unknown; the localized
OS architecture string alone cannot qualify a reference.

Every capture is `EvidenceKind: ObservedState`. WELA cannot prove that a machine is
a clean installation. A domain-joined machine's effective state may include domain
policy; a CI runner is customized. Neither is automatically a Windows default.

An independent reviewer should preserve the original capture and create a reviewed
copy only after checking the clean image, provisioning and effective GPO/MDM policy
evidence. Change `EvidenceKind` to `ReviewedCleanInstall`, and populate `Review`:

| Field | Required evidence |
|---|---|
| `Reviewer`, `ReviewedUtc` | Identified reviewer and explicit ISO-8601 UTC review time at/after capture, ending in `Z` |
| `ImageSha256` | SHA-256 of the clean installation image |
| `SnapshotId` | Reproducible VM/image snapshot identifier |
| `PolicyEvidenceSha256` | SHA-256 of retained effective GPO/MDM/provisioning evidence |
| `ProvisioningNotes` | Patch installation, join/promotion/CA steps, policy scope and deviations |

Do not remove observed Unknown entries or rewrite observations to match desired
recommendations. Keep the hashed image/policy artifacts with the review record.
`CapturedUtc` and `ReviewedUtc` must use `YYYY-MM-DDTHH:mm:ss[.fffffff]Z` (optional
one to seven fractional digits). Localized dates, missing timezone suffixes,
offset spellings and future timestamps are rejected; there is no clock grace
period. Preserve their original strings when editing the JSON artifact.
PowerShell 7.5 and later preserve timestamp strings with `-DateKind String`;
Windows PowerShell 5.1 preserves strings without that option. Earlier PowerShell 7
releases deserialize timestamps automatically, so an already deserialized
`DateTime` is accepted only with `Kind=Utc`, then subjected to the same ordering
and assessment-time checks. Local and unspecified `DateTime` values are rejected;
original lexical spelling cannot be revalidated after an older engine normalizes it.
The importer validates structure, fingerprints and exact scenario context;
it does not authenticate the reviewer or inspect external artifacts. Its report
explicitly labels that provenance as operator-declared. Duplicate IDs, missing
review fields, source/collector drift or any context mismatch prevent defaults
from being used. Unknown/missing individual observations remain Unknown even if
the reference otherwise qualifies. Hashes must be refreshed through a new review
when source or collector files change; do not relabel old observations blindly.

Before closing #385, capture independently reviewed clean Windows 11 24H2/25H2,
Server 2022/2025 member, promoted DC and AD CS scenarios with exact patches and
policy evidence. Include historical Application Guard-enabled/disabled clients
where still available. Synthetic fixtures test the comparison boundaries; native
Windows CI demonstrates read-only collection only. This PR includes no measured
clean-install snapshots or end-to-end event/ingestion evidence.

Sources: [Microsoft Application Guard removal](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/microsoft-defender-application-guard/md-app-guard-overview),
[Win32 processor platform codes](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-processor),
[localized OS architecture property](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem),
[CIS Windows benchmarks](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
(reviewed Windows 11 Enterprise v4.0.0, 18.10.44.1), and the versioned source records
in `config/audit_profiles.json`.
