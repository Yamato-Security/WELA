# Native public OneSettings configuration acceptance

The disposable acceptance fixture invokes the actual `WELA.ps1 audit-notifications` command under Windows PowerShell 5.1 and PowerShell 7. It verifies local configuration and the explicit Privacy channel dependency. It does not generate a OneSettings event or claim effective producer behavior, policy persistence, forwarding or Sigma readiness. Sysmon is excluded.

```powershell
./WELA.ps1 audit-notifications -NotificationAction Plan -NotificationControl OneSettings -EnablePrivacyChannel
./WELA.ps1 audit-notifications -NotificationAction Configure -NotificationControl OneSettings -EnablePrivacyChannel -DryRun
./WELA.ps1 audit-notifications -NotificationAction Configure -NotificationControl OneSettings -EnablePrivacyChannel -Auto -BackupPath C:\Evidence\onesettings-before -ResultsPath C:\Evidence\onesettings.json
```

Configure requires elevation and explicit control selection. Audit without a selection reads both notification controls. The CLI omits an unspecified control argument so these defaults and the required-selection error reach the command; passing an explicit null into the validated control parameter previously produced a binding error with a zero process exit.

Server 2022 requires the real installed `DataCollection.admx` machine mapping for `EnableOneSettingsAuditing` DWORD1, its existing native registry key and readable `Microsoft-Windows-Privacy-Auditing/Operational` metadata. Server 2025 remains unverified by the reviewed source and must refuse configuration. Tests preserve this gate; installing an ADMX alone does not establish support.

On Server 2022, `tests/OneSettingsConfigure.Windows.Tests.ps1 -AllowDisposableOneSettingsWrite` verifies:

- Plan and DryRun against an actually absent value and disabled channel, with no write journal or mutation.
- Policy-only Configure creates exactly DWORD1 and leaves the disabled channel unchanged.
- Explicit `-EnablePrivacyChannel` enables the channel after the producer policy is verified, preserving its existing larger buffer, retention, complete descriptor and other native configuration.
- A combined call from DWORD0 and a disabled channel writes policy then channel, retaining exact typed original records and native readback.
- Repeated configuration produces only AlreadyCompliant results and no write journal.
- Actual string and unreviewed DWORD2 values are preserved; failed producer prerequisites prevent the dependent channel action. Unsupported preview arguments are rejected before dispatch.

On Server 2025, Plan, Configure, DryRun and an explicit channel request exercise the existing unsupported-source refusal. They must not create the selected value, change a channel or write a pre-change journal. This is refusal evidence, not positive Server 2025 support.

The fixture is restricted to explicitly opted-in disposable GitHub-hosted standalone servers. Only the fixture temporarily prepares the selected value and channel. It retains original and restored typed policy, full channel XML, unrelated DataCollection values/descendants and owner/group/DACL, Security/System/Application/CAPI2 settings, service status/start type, Security warning/CrashOnAuditFail and all59 audit masks. Each cleanup check runs independently and records errors. Event records produced during testing are not restored. The fixture never clears a log, requests GPO refresh, modifies diagnostic-data upload policy or invokes a OneSettings download.

Owned public child processes have a three-minute deadline, bounded output, a bounded drain and confirmed termination before cleanup. The evidence manifest records commit, host/engine, source fingerprints and artifact hashes. These local hashes detect altered evidence; they are not signed attestation. Review the current four-way `Native public OneSettings configuration` workflow artifacts before relying on native acceptance.

The broader [audit-notifications guide](audit-notifications.md) describes prerequisites and remaining Windows11, DC/AD CS, event-generation and intended-reader/collector evidence for issue #378.
