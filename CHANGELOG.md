# CHANGELOG

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