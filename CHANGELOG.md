# CHANGELOG

## 2.2.0 [2026/xx/xx] - Dev Release

**Improvements:**

- Added opt-in `firewall-logging` audit, plan and configure actions for native Domain/Private/Public text logs, with allowed/dropped logging, minimum size checks, preserved operator paths/larger limits, and explicit CIS v4.0.0 paths. Configuration checks firewall service directory permissions, journals local/effective state and verifies effective policy without changing firewall enforcement or ACLs. Traffic and ingestion validation remains required. (#394) (@Shirofune-Security)
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
