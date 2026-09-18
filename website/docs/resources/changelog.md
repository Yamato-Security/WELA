# Changelog

!!! info
    This page mirrors the project [`CHANGELOG.md`](https://github.com/Yamato-Security/WELA/blob/main/CHANGELOG.md). See the [Releases page](https://github.com/Yamato-Security/WELA/releases) for downloads.

## 2.2.0 [2026/xx/xx] - Dev Release

**Improvements:**

- Added explicit CIS v4.0.0 Level 2 Windows PowerShell 5.1 transcription audit, plan and configure actions. An operator-selected existing output directory is checked and reported separately from policy; typed canonical registry writes are journaled, verified through shared 32/64-bit views and checked for drift while preserving invocation-header preferences. No ACL/share/retention changes or automatic Sigma EVTX credit are introduced; disposable native transcript tests restore original policy, and central authorization/collection remains a deployment check. (#405) (@Shirofune-Security)
- Added opt-in `ad-object-sacl` audit, plan, configure and conservative rollback actions for MDI domain/Exchange Configuration auditing and explicitly selected certificate template/enrollment service objects. Exact DC binding, schema GUID checks, additive SACL-only changes, pre-write SDDL/ACE receipts and read-back preserve existing security entries. Unknown optional dMSA prerequisites are reported as a separate skipped gap while the five independent domain class ACEs continue. Effective audit policy, inheritance/replication and 4662/5136 event evidence remain separate isolated-DC checks; no Sigma uplift is claimed. (#402) (@Shirofune-Security)
- Added opt-in `channel-settings` audit, plan and configure actions for Microsoft WEF Appendix C, including CAPI2 enablement, exact source byte sizes and an explicitly requested Event Log Readers read ACE. Existing descriptor components/ACEs and larger buffers are preserved or unsafe ACL edits are refused; shared journaling, fresh-state guards and readback report failures. Native Appendix E/F channel inventories exclude Sysmon/EMET and retain unverified identity access, generation and ingestion prerequisites. Windows lab evidence remains pending. (#401) (@Shirofune-Security)

- Added opt-in WMI namespace SACL audit, plan and configure actions based on ASD guidance, with explicit local namespace selection and separate descendant-inheritance consent. Full descriptor journals, SACL-only native requests, checked privilege restoration, race guards and read-back verification preserve existing permissions and unknown audit entries; event generation and forwarding remain separate lab validation. Verified native control-flag readback and idempotence on disposable Server 2022/2025 namespaces under PowerShell 5.1/7. (#399) (@Shirofune-Security)
- Added opt-in `firewall-logging` audit, plan and configure actions for native Domain/Private/Public text logs, with allowed/dropped logging, minimum size checks, preserved operator paths/larger limits, and explicit CIS v4.0.0 paths. Configuration checks firewall service directory permissions, journals local/effective state and verifies effective policy without changing firewall enforcement or ACLs. Traffic and ingestion validation remains required. (#394) (@Shirofune-Security)
- Unified event-log size auditing and configuration with shared byte-based profiles, including 256 MiB AppLocker/firewall logs, 32 MiB Setup and ASD 2048 MiB Security. Added separate source and collector size/mode choices through `-LogProfile` and `configure-eventlogs`; larger buffers and existing retention modes are preserved unless explicitly changed. Results include verified state and unknown retention duration. (#396) (@Shirofune-Security)

- Added opt-in `smb-auditing` audit, plan and configure actions for six native SMB audit policies. Host builds and exact local ADMX mappings gate writes; policy DWORDs and available runtime values are reported separately, with dry-run, recovery journaling and policy-registry verification. Runtime activation is reported separately as active, pending verification or unknown; an observed False does not turn a verified registry write into a failure. Signing/encryption requirements and guest access are not changed; runtime event/ingestion validation remains required. (#397) (@Shirofune-Security)
- Added versioned advanced audit-policy profiles shared by `audit-settings`, `plan` and `configure`: 59 subcategories and 14 profiles covering WELA, documented Windows defaults, Microsoft, reviewed CIS v4.0.0 and ASD native guidance. Profiles support role/build validation, offline planning and JSON exports with sources and prerequisites. Exact, minimum, optional, unchanged, Not Configured and not-applicable settings remain distinct. Windows defaults are reference-only; profile scope is advanced Security audit policy. (#390) (@Shirofune-Security)
- Added six native Windows audit subcategories to WELA's profile: Group Membership and Authorization Policy Change (Success), plus Application Group Management, MPSSVC Rule-Level Policy Change, IPsec Driver and Kernel Object (Success and Failure). Source-specific profiles retain their own audit settings and prerequisites; Kernel Object events require matching object SACLs, which this change does not create. (#391) (@Shirofune-Security)
- Added `-DryRun` and `-ResultsPath` to `configure` and `configure -Profile` to preview changes without modifying Windows settings and export per-control results as JSON. Commands that do not support `-DryRun` reject it before running. (#392) (@Shirofune-Security)
- Added `-BackupPath` and a recovery journal that records each control's previous state before making changes, with a documented manual recovery procedure. (#392) (@Shirofune-Security)
- Added a `configure-sacl` command that sets targeted audit SACLs on the autostart/persistence registry keys and sensitive files the detection rules watch, so File System (4663), Registry (4657) and Handle Manipulation (4656) auditing produce useful events without enabling global object auditing. It covers machine-wide objects plus per-user HKCU keys and profile AppData across all user profiles and the Default profile (so future users inherit the SACL). Targets live in `config/audit_sacl_targets.json`. (#361) (@YamatoSecurity)
- `configure` now also enables Detailed Tracking > Process Termination (4689), Object Access > Detailed File Share (5145), and (on domain controllers) LDAP query logging (Directory Service 1644 via NTDS `15 Field Engineering`), so a full detection baseline is applied without any manual `auditpol`/registry steps. (#361) (@YamatoSecurity)
- Baseline definitions were moved out of `WELA.ps1` into a `config/baselines.json` config file, so adding or changing a baseline is now a JSON-only edit. (#358) (@fukusuket)
- The `Microsoft-Windows-DFSN-Server/Admin` channel is now checked by `audit-settings` and `audit-filesize`. (#358) (@fukusuket)
- MITRE ATT&CK Navigator heatmaps are now generated for ATT&CK v19, and technique IDs that ATT&CK has revoked are rewritten to their replacements (for example `T1562` and `T1562.001`, which v19 folded into `T1685`). Navigator silently discards revoked entries, so that coverage used to disappear from the heatmap. (@fukusuket)

**Bug Fixes:**

- Both `configure` paths now journal and verify `SCENoApplyLegacyAuditPolicy=1` (DWORD) before applying advanced audit subcategories. Failed or declined precedence changes block dependent writes; pre-write and final checks detect drift. Profile plans report precedence state and available last-applied RSoP evidence without claiming persistence through policy refresh. (#393) (@Shirofune-Security)
- Replaced static native-channel `Enabled` claims with actual channel state, mode and ACL reads plus provider prerequisite observations. AppLocker, NTLM, Defender and other native sources remain conditional until event generation is validated; channel enablement alone grants no usable-rule credit. Added JSON/HTML audit assessment exports preserving denied/absent states and source evidence. Rule channel patterns now match concrete catalog channels consistently during filtering and source mapping. (#395) (@Shirofune-Security)
- Fixed `configure` enabling outgoing NTLM blocking by default. It now sets Audit all (`RestrictSendingNTLMTraffic=1`) for unset or Allow policies while preserving existing Deny all (`2`) and unknown values/types. Use `-OutgoingNtlmMode Audit` to explicitly replace a deny policy, or `Deny` to enable blocking. Configuration rechecks policy before writing, verifies changes, reports failures, and displays the observed policy and available last-applied RSoP information. (#388) (@Shirofune-Security)
- `audit-settings` now reports role-inapplicable audit policies as `Not applicable` and excludes them from category enablement totals. NTLM policy values are interpreted and verified only when stored as DWORDs. (#392) (@Shirofune-Security)
- Configuration now checks native command exit codes, verifies settings after applying changes, and checks them again before finishing. Failed writes, ineffective changes, CA restart failures and settings that no longer match at the final check produce explicit results and a nonzero exit code instead of unconditional success. (#392) (@Shirofune-Security)
- Fixed domain NTLM auditing: `configure` now sets `AuditNTLMInDomain=7` (Enable all) only on confirmed domain controllers, instead of writing `2` on every host. This setting is left unchanged on other hosts and hosts whose role cannot be determined. Audit output reports the domain NTLM setting, and configuration verifies registry writes and reports failures. (#389) (@Shirofune-Security)
- Rule filtering applied only the last criterion instead of all of them, so rule counts were inaccurate. (#358) (@fukusuket)
- Rules were reported as usable even when the logs they depend on were disabled. (#358) (@fukusuket)
- Rules that belong to multiple categories were counted and written to the CSV files multiple times. (#358) (@fukusuket)
- Rules that did not match any category were dropped from the CSV files and from the coverage total. They are now reported under `Uncategorized`. (#358) (@fukusuket)
- The utilization threshold was compared as a string, so the percentage was shown in the wrong color. (#358) (@fukusuket)
- `Success and Failure` was shown in red even though auditing was enabled. (#358) (@fukusuket)
- The MITRE ATT&CK Navigator layer contained invalid technique IDs and was written as UTF-16, which ATT&CK Navigator cannot read. (#358) (@fukusuket)
- Running WELA from a directory other than the one it is installed in failed. (#358) (@fukusuket)
- `audit-filesize` aborted the whole check when a single log was missing. (#358) (@fukusuket)
- PowerShell logging settings were only read from the 32-bit registry view, so a machine configured by GPO was reported as `Disabled`. (#358) (@fukusuket)
- Parsing of the `auditpol` output could fail, and running `audit-settings` without Administrator privileges produced a confidently wrong report. (#358) (@fukusuket)
- `configure -Baseline ASD` silently applied the YamatoSecurity settings. (#358) (@fukusuket)
- A failed download in `update-rules` could corrupt the existing config files. (#358) (@fukusuket)
- CSV output was inconsistent between the `std`, `table` and `gui` output types. (#358) (@fukusuket)
- The release and CSV creation GitHub Actions workflows were failing. (#358) (@fukusuket)

**Note:** because of the fixes above, the reported utilization is now lower than in 2.1.0 (23.38% -> 12.94% on the same machine). The new number is the correct one: rules whose logs are disabled are no longer counted as usable, and rules that were previously dropped are now included in the total.

## 2.1.0 [2026/02/13] - Winter Release

**Bug Fixes:**

- Configuration might break Netlogon on Domain Controllers. (#243) (@fukusuket) (Thanks to @feiglein74 for reporting this!)

## 2.0.0 [2025/11/16] - CODE BLUE Release

**New Features:**

- Added `applocker-readiness` to inspect native policy collections, enforcement, Application Identity and channels, plus a guarded operator-supplied audit-only import for empty local policies. Existing enforcement and managed hosts block import; unused empty NotConfigured placeholders no longer cause false comparison failures, while targeted placeholders remain blocked because merge can retain enforcement. Original XML and unknown/configured collection content stay preserved; GP/CSP visibility and event-generation gaps remain explicit. (#400) (@Shirofune-Security)
- Profile plan/audit/configure now include read-only targeted SACL prerequisites with object policy masks, per-user hive and redirected-folder gaps, exact WEF Run/RunOnce audit entries, and an explicit `-SaclMode Skip`. User-file targets retain their configured suffix under the user's AppData or Startup known folder; unsupported or ambiguous paths remain unresolved. No SACL writes or unverified detection uplift are implied. (#398) (@Shirofune-Security)


- Support for MITRE ATT&CK Navigator heatmaps. (#11) (@fukusuket)
- Added a `configure` command to configure Windows settings to various baselines. (#12) (@fukusuket)
- Support for Defender for Identity required logs. (#114) (@fukusuket)

**Bug Fixes:**

- Some of the rule count was not accurate. (#99) (@fukusuket)
- TaskScheduler log settings were not accurately reported. (#100) (@fukusuket))

## 1.0.0 [2025/05/20] - AUSCERT/SINCON Release

**New Features:**

- `audit-settings`: Check Windows Event Log audit policy settings.
- `audit-filesize`: Check Windows Event Log file size.
- `update-rules`: Update WELA's Sigma rules config files.
