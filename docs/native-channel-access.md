# Native channel settings and CAPI2 access

`channel-settings` audits, plans and optionally applies the native channel examples in Microsoft's WEF Appendix C. Its separate query inventory identifies the channels required by the selected Appendix E/F queries. This is an opt-in command; ordinary `configure` does not change channel ACLs.

```powershell
.\WELA.ps1 channel-settings -ChannelAction Audit -WefQuerySet Baseline -ResultsPath channels.json
.\WELA.ps1 channel-settings -ChannelAction Plan -WefQuerySet Both -GrantEventLogReaders -ResultsPath plan.json
.\WELA.ps1 channel-settings -ChannelAction Configure -GrantEventLogReaders -DryRun -ResultsPath preview.json
# Elevated Windows shell, after reviewing the plan; prompts unless -Auto is supplied:
.\WELA.ps1 channel-settings -ChannelAction Configure -GrantEventLogReaders -BackupPath C:\WELA-Recovery\channels-run1 -ResultsPath result.json
```

The named `-ChannelProfile microsoft-wef-appendix-c` is the only profile. `-WefQuerySet Baseline|Suspect|Both` selects **inventory**, not which Appendix C controls are applied. Audit and Plan never modify Windows. Configure always requests the three declared enable/size controls; adding the CAPI2 reader ACE additionally requires `-GrantEventLogReaders`. Without it, the existing descriptor is preserved and a missing read grant remains an unmet prerequisite. JSON exports include the full current/proposed descriptor, source bytes, native read failures, query IDs and unverified prerequisites. Access failures stay unknown; unregistered channels stay not installed and require role/query review.

| Channel | Enabled setting | Source example bytes | Rounded minimum applied | Access request |
|---|---|---:|---:|---|
| Microsoft-Windows-CAPI2/Operational | Enable | 102432768 | 102432768 | Event Log Readers read, explicit opt-in |
| Microsoft-Windows-AppLocker/EXE and DLL | Preserve | 102432768 | 102432768 | Preserve |
| Microsoft-Windows-DriverFrameworks-UserMode/Operational | Enable | 52432896 | 52494336 | Preserve |

The source examples are **not** 100 MiB and 50 MiB. Larger existing limits and retention modes are preserved. These are channel buffer examples, not promised retention duration. Source: [Microsoft WEF Appendix C](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection#appendix-c---event-channel-settings-enable-and-channel-access-methods). Applied limits round upward to a 64 KiB unit as required by [wevtutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil).

## Permission and mutation boundaries

The appended ACE grants SID `S-1-5-32-573` (Event Log Readers) **read only**, access mask `0x1`. Existing ACEs are not broadened or removed; even an existing write-only grant is retained and a separate read ACE is appended. WELA does not copy Microsoft's complete example descriptor over the host descriptor. Event Log read, write and clear are separate [Windows access constants](https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log-constants).

The planner uses [RawSecurityDescriptor](https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.rawsecuritydescriptor?view=netframework-4.8.1), clones its binary representation, inserts an explicit allow before the first inherited ACE and verifies an exact binary round trip through the proposed SDDL. Owner, group, SACL, control flags and every existing ACE byte/order must survive. No ACL canonicalization occurs. Absent/null DACLs, any applicable read-deny ACE, unknown ACEs and descriptors that cannot round-trip losslessly require manual review and are left unchanged. Recognized object/callback ACEs are retained only if lossless serialization succeeds. This conservative rule may decline descriptors that an administrator can safely edit manually.

`GrantPresent` describes an unconditional group read ACE in the descriptor. It **does not establish effective read access** for any user or service token. Group membership, denied groups, privileges, actual event reads and forwarding remain separate. Read permission also does not establish AppLocker policy, provider generation readiness, or Sigma rule usability.

The shared configuration runner writes `before.jsonl` before each native mutation, capturing the original enabled state, exact size, full descriptor and retention mode. A fresh read must match both the plan and the journal snapshot before `wevtutil sl` executes. Only changed `/e:true`, `/ms:...` and explicitly authorized `/ca:...` arguments are sent. Native failure, failed readback, descriptor mismatch and final drift produce a nonzero result. There is no atomic Windows compare-and-set; another writer can still race the final check. Re-run after policy refresh to check persistence. No automatic rollback occurs.

Recovery is manual: review each journal `Before` against the current settings, identify the affected channel, and restore only the intended previous values using `wevtutil sl "CHANNEL" /e:true|false /ms:ORIGINAL_BYTES /ca:"ORIGINAL_SDDL"`. Pass the descriptor as one argument in PowerShell, for example `& wevtutil.exe sl $entry.Target.Channel ("/ca:" + $entry.Before.SecurityDescriptor)` after loading and reviewing the relevant JSONL entry. Restoring a smaller limit can discard events. Existing retention is not intentionally modified; investigate any changed mode before choosing recovery actions. Use a new backup directory for each run.

## Native WEF prerequisites and validation

The checked-in inventory maps source query IDs to 12 baseline channels and 8 suspect channels (18 unique combined). Baseline queries 12 (EMET) and 39 (Sysmon) are explicitly excluded. Native-only scope excludes external agents; channel settings do not create subscriptions, add service identities to groups or configure WinRM/collectors. The Microsoft [source prerequisite guidance and sample queries](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection) remain a starting point for reviewing role applicability. The report always lists token/group membership, producer configuration, representative event generation and forwarding/ingestion as unverified; required disabled or missing channels remain visible. Other inventoried channels are not automatically enabled.

Safe tests exercise the actual command/JSON/runner with mocked Windows setters. Windows PowerShell 5.1 and PowerShell 7 CI additionally exercise real descriptor serialization and read-only CLI inspection. Release packaging already includes the whole `config`, `modules` and `scripts` directories.

**Isolated Windows acceptance evidence is still pending; related to issue #367, not sufficient to close it.** On patched Windows 11, member server, DC and ADCS snapshots where the channels exist:

1. Save the plan, channel metadata, descriptor and policy context. Review capacity and the intended forwarding identity. Capture the actual identity/token memberships separately.
2. Apply the opt-in profile, retain the journal/results, then independently read enablement, exact bytes and full SDDL. Compare all original ACEs plus owner/group/SACL/flags and repeat after policy refresh.
3. Using the intended forwarding identity's actual token, read CAPI2 event records. An administrator's successful query or a matching group ACE is insufficient evidence. Record denied/missing cases explicitly.
4. Generate a benign native event appropriate to the isolated role, retain its XML and verify matching collector ingestion under the intended subscription. WELA does not perform this test or claim any measured Sigma coverage increase.
