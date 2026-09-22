# Versioned advanced audit-policy profiles

`audit-settings`, `plan`, and `configure` share `config/audit_profiles.json` for advanced Security audit policy. The ordinary `audit-settings -Baseline YamatoSecurity` and ordinary `configure` also use `wela-2.2.0`, eliminating a separate hard-coded configuration list. All 59 subcategories use canonical GUIDs, including categories missing from the older display catalog.

**Profile definitions cover advanced audit policy.** Configuration also verifies and enables its `SCENoApplyLegacyAuditPolicy=1` DWORD prerequisite before applying subcategories. Selecting Microsoft, CIS or ASD does not configure their PowerShell settings, command-line capture, channel buffers, NTLM policy, firewall logs, SACLs, CA AuditFilter, forwarding or retention. This is not a claim of full baseline compliance or detection coverage. Sysmon and external sensors are outside this feature. Ordinary `configure` without `-Profile` continues the existing broader WELA setup, with its advanced audit portion supplied by the shared profile.

For operator-owned settings, see [custom profile files](custom-audit-profiles.md). `-ProfileFile` selects a strictly validated file without editing or overriding built-in profiles.

## Commands

```powershell
# List exact profile ids and role/build applicability.
.\WELA.ps1 profiles

# Offline planning is available on any platform; unknown effective state stays Unknown.
.\WELA.ps1 plan -Profile wela-2.2.0 -Role Client -Build 26100 -PlanPath plan.json

# On Windows, omit Role/Build to detect this host and read effective auditpol values.
.\WELA.ps1 audit-settings -Profile microsoft-sct-win11-24h2 -PlanPath audit.json

# Apply advanced audit policy and its precedence prerequisite. Interactive unless -Auto is supplied.
.\WELA.ps1 configure -Profile asd-native-2021-10 -Auto -PlanPath result.json

# Select optional File System/Registry policy flags, without creating SACLs.
.\WELA.ps1 configure -Profile asd-native-2021-10 -IncludeOptional -PlanPath result.json
```

Supply both `-Role` and `-Build`, or omit both for Windows host detection. Roles are `Client`, `MemberServer`, `DomainController`, and `ADCS` (CA on a member server). Combined DC/CA deployments are not supported by these role profiles: host detection refuses them before configuration writes, rather than silently omitting CA auditing. A failure to read the CA installation state is also an error, not evidence of a member server without CA. Build means the base build, for example 20348 (Server 2022), 26100 (Windows 11 24H2 / Server 2025), or 26200 (Windows 11 25H2). Live application checks the actual Windows host; a supplied role/build cannot authorize applying a mismatched plan. Versioned SCT profiles reject other base builds. Unsupported profiles/hosts and unreadable policies fail before writes.

The WELA and documentary guide profiles currently cover the reviewed Windows 11/Server 2022/Server 2025 range. Older/future operating systems require a reviewed applicability update. `-Baseline` retains the legacy display interface for non-Yamato guides; use `-Profile` to select the versioned shared definitions. Do not combine `-Baseline` and `-Profile`.

## Included sources

| Profile | Version / meaning |
| --- | --- |
| `wela-2.2.0` | Reviewed WELA development snapshot `8ef938f0966e86adc527395f50f907c43e843d1e`; extends the 34 existing policies with [six native audit controls](../website/docs/commands/native-audit-controls.md), with irrelevant roles skipped and three SACL prerequisites optional |
| `windows-defaults-reviewed-2026-09` | Documentary effective-default model; **reference only**, cannot be applied or used to reset an OS |
| `microsoft-sct-win11-24h2`, `microsoft-sct-win11-25h2` | Official SCT Policy Analyzer settings, exact masks |
| `microsoft-sct-server2022`, `microsoft-sct-server2025-2602` | Official SCT member/DC settings; AD CS uses the member-server baseline |
| `microsoft-stronger-reviewed-2026-09` | Stronger audit recommendation column; minimum enabled flags, conditional IPsec opt-in; ambiguous unspecified success/failure values preserved |
| `microsoft-wef-reviewed-2026-09` | WEF Appendix A minimum audit policy, preserving explicit Not Configured |
| `microsoft-identity-reviewed-2026-09` | Identity collection's DC/CA advanced audit requirements only; other prerequisites remain separate |
| `cis-win11-v4-l1`, `cis-win11-v4-l2` | Historical Windows 11 Enterprise v4.0.0, retaining “includes” minimum semantics |
| `cis-server2022-v4-l1`, `cis-server2022-v4-l2` | Historical Server 2022 v4.0.0, role-aware DC requirements |
| `asd-native-2021-10` | ASD native fallback; optional object auditing and explicit Detailed File Share Not Configured |

CIS v4.0.0 is not the latest CIS edition. Defaults combine documentary evidence that is not a clean-install measurement, and some Server values are shared across roles. The defaults profile is deliberately blocked from application. Source URLs, versions, setting-level evidence, notes and prerequisites are in the JSON and exported plans. The catalog GUID reference is [Microsoft MS-GPAC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d).

## Policy semantics

Mask bits are Success `1`, Failure `2`, both `3`, neither `0`.

| Mode | Behavior |
| --- | --- |
| `exact` | Set the exact mask; may remove an existing success/failure flag |
| `minimum` | Bitwise OR with fresh effective state, preserving additional auditing |
| `unchanged` | Preserve current state; every omitted control becomes an explicit unchanged plan row |
| `not-configured` | Preserve effective policy; do not interpret it as disabled and do not remove a GPO |
| `optional` | Preserve unless `-IncludeOptional` is supplied; then set the explicit mask |
| `not-applicable` | Preserve; skip a subcategory outside the selected role |

For example Detailed File Share is exact S+F in WELA, minimum Failure in the reviewed CIS profiles, and Not Configured in ASD. These are deliberate differences, not a universal “enable everything” preset. Omitted values and unknown effective state are different: unknown state blocks application instead of becoming mask zero.

Effective policy is read through the Windows [AuditQuerySystemPolicy API](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy); localized `auditpol /get /r` text is not parsed. Apply reads effective state immediately before each control, checks native command errors, then verifies each changed policy. Minimum policies only enable required native flags, never disable additional flags, and accept any effective state containing the required bits. Exact policies require the exact mask. A command that exits successfully but does not change effective policy is reported as failed. Group Policy can reapply after a successful verification: these are local effective-policy changes, not GPO authoring. Exported plan/current state and apply results include the profile version, schema SHA-256, source provenance, before/target/effective masks and failure details. This feature does not validate event generation, SACL correctness, ingestion, or Sigma field compatibility.

## Extending the schema and testing

Add a catalog entry with a unique GUID, category, supported roles and prerequisite text. Add or override profile controls using `mode`, `mask` (only for exact/minimum/optional), optional `note`, `evidence`, and `sourceIds`. A profile supplies `sourceIds`, an explicit role/build range, `omitted: unchanged`, and `scope: advanced-audit-policy-only`. Optional control source ids are added to profile provenance. Do not silently revise a published source version when its semantics change.

```powershell
# Pure tests, including injected native boundaries; no policy changes or elevation.
pwsh -NoProfile -File tests/audit-profiles.Tests.ps1
powershell -NoProfile -File tests/audit-profiles.Tests.ps1
```

The tests cover source/schema validation, role/build gating, exact/minimum/optional/NC behavior, locale-independent native policy reads, unknown-state refusal, fresh-state merging, idempotence, failed commands and verification, and the ordinary Yamato audit display. CI runs these on Windows PowerShell 5.1 and PowerShell 7. Source review and mocked tests are not substitutes for checking effective policy and benign event XML on isolated Windows clients, member servers, DCs and CAs.

## Advanced audit precedence

Both configure paths journal and verify `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy=1` (DWORD). Declining or failing this prerequisite skips dependent audit-policy writes. Every actual subcategory write rechecks precedence, and final verification detects later registry or effective-mask drift. Profiles selecting no audit controls do not change the prerequisite. `plan` and `audit-settings -Profile` include `AuditPrecedence` evidence; offline plans leave its live state Unknown. The result scope is `advanced-audit-policy-and-precedence`; profile-definition scope remains `advanced-audit-policy-only`.

Matching last-applied RSoP GPO IDs are reported where readable. The reader handles the documented `RSOP_RegistryPolicySetting` (`registryKey`, `valueName`, DWORD byte data), `RSOP_SecuritySettingNumeric` (`KeyName`, `Setting`) and `RSOP_RegistryValue` (`Path`, `Type`, `Data`) schemas separately. Only canonical 0/1 values in a recognized DWORD/numeric representation are decoded; other encodings retain their source and raw evidence with unknown conflict status. Deleted registry-policy entries are ignored. All matched observations remain in `Matches`. RSoP may be stale and does not identify the current writer. A reported 0 is flagged as conflicting with the desired value; unrecognized RSoP encodings remain unknown. Local success is a point-in-time observation, not proof of persistence through Group Policy or MDM refresh. WELA does not run `gpupdate` implicitly.

See [Microsoft's precedence policy documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/audit-force-audit-policy-subcategory-settings-to-override). This prevents legacy category policy from replacing subcategory settings; it does not supersede other advanced-audit policies.

For recovery, review the journal and restore the exact prior registry value/type (or remove only the value if it was previously absent), then restore reviewed subcategory settings. Never delete the Lsa key. In an isolated joined Windows VM, create a conflicting legacy category GPO, record `gpresult /scope computer /h before.html`, and capture `auditpol /get /category:* /r`. Apply WELA, explicitly refresh with `gpupdate /target:computer /force`, then rerun `audit-settings -Profile <selected-profile> -PlanPath after.json` and the auditpol capture. Verify registry precedence, each effective mask and GPO provenance; retain the snapshots and benign event XML. This domain-refresh/event test remains pending; CI exercises injected failures/drift and read-only Windows observations.

RSoP schema references: [registry policy](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/rsop-registrypolicysetting), [numeric security setting](https://learn.microsoft.com/en-us/previous-versions/aa375064(v=vs.85)), and [security registry value](https://learn.microsoft.com/en-us/previous-versions/aa375052(v=vs.85)). Tests use these actual property shapes; they do not substitute a shared synthetic schema.

Targeted file/registry SACL prerequisites are included as a read-only companion plan. See [targeted SACL planning](targeted-sacl-planning.md) for per-user gaps, source distinctions and `-SaclMode Skip`.

The stronger profile's optional IPsec Main Mode control additionally requires positive local native prerequisite evidence during shared planning/configuration. See [conditional IPsec prerequisites](ipsec-prerequisites.md) for scope, statuses and fresh pre-write checks.

A separate [public custom-profile native acceptance fixture](custom-audit-profiles.md#verification-and-recovery) exercises the shared configuration/precedence engine with actual writes on disposable Server 2022/2025 hosts. It verifies all 59 effective masks and exact cleanup without claiming full baseline, GPO, event or Sigma acceptance.
