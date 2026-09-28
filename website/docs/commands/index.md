# Command list

WELA 3.0 provides the commands below. Run `./WELA.ps1 <command> -Help` for the
options and safety boundaries of a command. Configuration commands support only
the options shown in their help; WELA rejects options that belong to another
command.

## Profiles, assessment, and configuration

| Command | Purpose |
| --- | --- |
| `profiles` | List built-in or validated custom advanced-audit profiles. |
| `plan` | Build an offline plan for a selected advanced-audit profile. |
| `audit` | Compare a selected advanced-audit profile with live policy. |
| `audit-settings` | Assess live logging and audit readiness with a legacy baseline or versioned profile. |
| `eventlog-profiles` | List event-log size and retention-mode profiles. |
| `audit-filesize` | Read live event-log sizes and retention modes. |
| `configure-eventlogs` | Apply a reviewed event-log size or mode profile. |
| `configure` | Configure native logging controls or a selected advanced-audit profile. |
| `configure-sacl` | Add the legacy targeted file and registry audit SACL set. |
| `audit-integrity` | Audit, plan, or configure audit rights and failure policy. |
| `audit-notifications` | Audit or configure OneSettings and Security-log warning controls. |
| `retention-health` | Assess bounded local retention, archival, and forwarding health. |
| `event-measurement` | Plan or measure bounded delivery rates for one existing channel. |
| `rule-eligibility` | Calculate evidence-aware Sigma rule eligibility. |
| `score` | Report separate configuration-compliance and evidence-readiness scores. |
| `control-applicability` | Assess historical feature, role, build, and edition applicability. |
| `default-evidence` | Capture or compare exact-context Windows default evidence. |

## Native logging and audit controls

| Command | Purpose |
| --- | --- |
| `dns-analytical` | Audit or configure the DNS Server analytical-channel lifecycle. |
| `targeted-sacl` | Audit, plan, or configure selected existing local SACL targets. |
| `adcs-auditing` | Audit or configure local AD CS auditing with explicit restart consent. |
| `ldap-diagnostics` | Audit or configure role-scoped LDAP 1644 diagnostics. |
| `provider-packs` | List, audit, plan, or configure optional native provider packs. |
| `channel-read` | Test actual current-token read access to selected channels. |
| `channel-settings` | Audit or configure selected native channel settings and read access. |
| `wmi-auditing` | List, audit, plan, or configure selected WMI namespace SACLs. |
| `firewall-logging` | Audit or configure native Windows Firewall text logging. |
| `smb-runtime` | Plan or explicitly activate selected SMB runtime audit switches. |
| `smb-auditing` | Audit or configure version-aware SMB audit policy. |
| `process-commandline` | Audit or configure Security 4688 command-line recording. |
| `powershell-logging` | Audit or configure selected Windows PowerShell event policies. |
| `powershell-transcription` | Audit or configure Windows PowerShell transcription. |
| `ntlm-auditing` | Audit or configure incoming and domain NTLM auditing. |
| `outgoing-ntlm` | Audit or configure outgoing NTLM auditing independently. |
| `ad-object-sacl` | Audit or configure selected AD and AD CS object SACLs. |
| `applocker-readiness` | Assess AppLocker readiness or import a guarded audit-only policy. |

See [Native audit controls and prerequisites](native-audit-controls.md) for the
policy masks and evidence limitations shared by these commands.

## Windows Event Forwarding and collection

| Command | Purpose |
| --- | --- |
| `wef-source` | Audit, plan, or configure native domain/Kerberos WEF source settings. |
| `wef-query` | Execute one selected source QueryList locally. |
| `wef-arrival` | Verify exact probe-event arrival on the local collector. |
| `wec-collector` | Audit, plan, or create a reviewed collector subscription. |
| `wec-runtime` | Read bounded native subscription runtime state. |
| `wec-listener` | Plan or create one reviewed HTTP 5985 collector listener. |
| `wec-ingress` | Plan or create one scoped collector firewall rule. |
| `wec-authorization` | Review or apply source-SID authorization to one subscription. |
| `wec-state` | Review or apply enable/disable state to one subscription. |
| `wec-update` | Review or apply query and description updates to one subscription. |

## Evidence probes and validation

| Command | Purpose |
| --- | --- |
| `registry-probe` | Generate and correlate one owned registry-value event. |
| `file-access-probe` | Generate and correlate one bounded audited file read. |
| `dns-client-probe` | Generate and correlate one fixed DNS client lookup. |
| `capi2-probe` | Generate and correlate one offline CAPI2 chain event. |
| `failed-logon-probe` | Generate and correlate one fixed local failed logon. |
| `wmi-probe` | Generate and correlate one fixed local WMI read. |
| `applocker-script-probe` | Collect one fixed AppLocker script decision event. |
| `applocker-probe` | Collect one fixed AppLocker executable decision event. |
| `transcript-probe` | Verify one automatic Windows PowerShell 5.1 transcript. |
| `native-validation` | Collect a fixed native Security 4688 probe without changing policy. |

## Reviewed recovery

| Command | Purpose |
| --- | --- |
| `registry-sacl-recovery` | Review removal of one proven registry audit ACE. |
| `file-sacl-recovery` | Review removal of one proven file audit ACE. |
| `wmi-sacl-recovery` | Review removal of one proven parent WMI audit ACE. |
| `transcription-recovery` | Review restoration of one transcription configuration. |
| `audit-recovery` | Review restoration of supported audit and logging controls. |
| `channel-recovery` | Review restoration of one channel-settings operation. |
| `eventlog-recovery` | Review restoration of one event-log size or mode operation. |
| `firewall-recovery` | Review restoration of one firewall text-log operation. |
| `evtx-recovery` | Export or verify recoverable events from an existing EVTX file. |
| `adcs-resume` | Review and resume a pending AD CS auditing restart. |

## Deployment and export

| Command | Purpose |
| --- | --- |
| `gpo-create` | Create a new disabled, unlinked GPO from a reviewed genuine backup. |
| `gpo-package` | Plan, export, or verify offline GPO audit components. |
| `intune-export` | Export and verify offline Intune audit-policy artifacts. |

## Maintenance and help

| Command | Purpose |
| --- | --- |
| `update-rules` | Update WELA's detection-rule configuration files. |
| `version` | Print the WELA version and release status. |
| `help` | Print public CLI examples and command help pointers. |

Detailed implementation, validation, and recovery guides are maintained in the
repository [`docs/` directory](https://github.com/Yamato-Security/WELA/tree/dev/docs)
and are included with release packages.
