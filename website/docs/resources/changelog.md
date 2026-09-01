# Changelog

!!! info
    This page mirrors the project [`CHANGELOG.md`](https://github.com/Yamato-Security/WELA/blob/main/CHANGELOG.md). See the [Releases page](https://github.com/Yamato-Security/WELA/releases) for downloads.

## 2.2.0 [2026/08/31] - Dev Release

**Improvements:**

- Baseline definitions were moved out of `WELA.ps1` into a `config/baselines.json` config file, so adding or changing a baseline is now a JSON-only edit. (#358) (@fukusuket)

**Bug Fixes:**

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
