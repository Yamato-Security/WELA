# Windows PowerShell transcription (CIS Level 2)

`powershell-transcription` provides an **explicit, optional Level 2** transcription policy for Windows PowerShell 5.1. It is separate from advanced audit-policy profiles and is never automatically enabled by an L1 profile, `configure`, or script-block/module logging. The reviewed CIS Windows 11 Enterprise and Windows Server 2022 **v4.0.0**, section **18.10.87.2**, require `EnableTranscripting=1` at Level 2. This command is not a complete CIS compliance assessment and does not claim the latest benchmark version.

```powershell
# Read current machine/current-user policy and destination observations.
./WELA.ps1 powershell-transcription -TranscriptionAction Audit -ResultsPath transcription-audit.json

# Select and review an existing destination before configuration.
./WELA.ps1 powershell-transcription -TranscriptionAction Plan `
  -TranscriptDirectory C:\Transcripts -ResultsPath transcription-plan.json
./WELA.ps1 powershell-transcription -TranscriptionAction Configure `
  -TranscriptDirectory C:\Transcripts -DryRun -ResultsPath transcription-preview.json

# Configure only after reviewing the directory's intended writers and collectors.
./WELA.ps1 powershell-transcription -TranscriptionAction Configure `
  -TranscriptDirectory '\\collector.example.test\Transcripts' `
  -Auto -BackupPath .\new-transcription-backup -ResultsPath transcription-result.json
```

`Plan` and `Configure` require `-TranscriptDirectory`. The path must be an existing literal absolute drive or UNC directory. Relative paths, environment variables, wildcards, dot segments, device paths, alternate streams and observed reparse-point components are rejected. The command never provisions a directory, share or ACL. `-Auto` accepts the ordinary configuration prompt; it does not prove that destination permissions are suitable. `-Profile` and `-Baseline` are rejected by this command, and transcription-specific parameters are rejected on unrelated commands. `-DryRun` is supported only with `Configure` and writes neither policy nor a recovery directory.

## Policy and engine scope

The machine policy key is:

```text
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
```

| Value | Requested state | Treatment |
| --- | --- | --- |
| `EnableTranscripting` | REG_DWORD `1` | Explicitly enabled for CIS L2 |
| `OutputDirectory` | REG_SZ containing the operator's exact absolute path | Verified before enablement |
| `EnableInvocationHeader` | Existing value, type or absence | Observed and preserved; not required by this CIS check |

An explicit configuration repairs incorrect types such as REG_SZ `"1"` for `EnableTranscripting`. Unrelated values and current-user policy are preserved. Computer policy takes precedence over user policy, but this command reports observed registry state and does not claim GPO/MDM ownership or persistence. A policy refresh can override a direct registry write; manage the authoritative policy separately. [Microsoft Windows PowerShell policy documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings?view=powershell-5.1), [ADMX mapping](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-powershellexecutionpolicy#enabletranscripting).

The required explicit output-directory review is a WELA deployment safeguard; the cited CIS check itself requires enablement and does not mandate a particular output path or invocation-header choice.

Microsoft documents `HKLM\SOFTWARE\Policies` as **shared** by 32-bit and 64-bit processes. WELA reads the canonical path through both registry views on a 64-bit OS and refuses inconsistent observations. It writes once through the native view; it does not create a literal `Wow6432Node` policy subtree. [WOW registry sharing documentation](https://learn.microsoft.com/en-us/windows/win32/winprog64/shared-registry-keys).

Installed Windows PowerShell 5.1 is checked using its engine registry version and executable presence. WELA can run under Windows PowerShell 5.1 or PowerShell 7 on Windows, but the target remains **Windows PowerShell 5.1**. PowerShell 7 uses separate PowerShell Core policy/configuration, including an optional Windows-policy fallback; this command does not configure or assess that fallback. No PowerShell 7 session coverage is inferred. Existing sessions are not restarted or asserted to adopt a changed policy. [PowerShell 7 policy documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings?view=powershell-7.5).

## Destination review and collection

Transcripts contain command input and output and can contain credentials or other sensitive data. The command deliberately requires a selected output location instead of silently accepting each user's Documents directory. Microsoft recommends restricting access when transcripts are centralized. [Microsoft transcription guidance](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings?view=powershell-5.1#turn-on-powershell-transcription).

The plan/result includes the directory's resolved path, creation time, attributes, owner, DACL SDDL and recognized ACEs. A null/empty DACL, or an identified broad read/list or modification grant, blocks configuration. Broad principals include Everyone, Authenticated Users, Users, Guests, Anonymous, Network and Interactive. Grant inspection is deliberately conservative: a deny ACE does not automatically cancel a reported broad allow. Conditional or uninterpreted access ACEs and failed reads remain `Unknown` and block configuration. WELA makes no ACL changes to work around these findings.

`Destination.Status=Observed` means the directory was read without those identified grants. **It is not an effective-access or storage-security certification.** Arbitrary group membership, each run-as identity, protected child ACLs, ownership, deny interactions and a collector's access remain deployment checks. For UNC destinations, the readable filesystem DACL is observed while `ShareAuthorization=Unknown` remains explicit; the client does not inspect remote SMB share permissions or server quotas. Explicit `Configure` may proceed with this UNC uncertainty after the operator reviews the deployment. `WriterAuthorization` and `CollectorAuthorization` remain `Unknown` in all normal reports.

Before rollout, provision a dedicated destination and verify that intended writers can create the date subdirectories and transcript files, while unauthorized users cannot read, replace or delete other users' transcripts. Limit collector/reviewer access, test both NTFS and SMB permissions for actual identities, and use an appropriate collection/retention design. A local administrator-only directory is suitable for the disposable CI test, not proof that ordinary user sessions can write centrally. WELA does not copy an ACL recipe across deployments or claim append-only/immutable storage.

Plan capacity and retention separately: estimate daily transcript volume and peak sessions; set and monitor storage quotas/free space; define retention, rotation, archival and deletion ownership; and confirm the collector reads complete files with the correct identity and protects the destination. No quota, scheduled cleanup, SMB permission, retention policy, encryption or collection configuration is changed. Local transcript production cannot establish central ingestion.

## Verification and recovery

One configuration control journals the original typed machine/current-user values from both views and destination observations to `before.jsonl` before any registry mutation. A fresh policy/directory check after the prompt refuses drift. The reviewed `OutputDirectory` is written and reread **before** `EnableTranscripting` is enabled. Post-write and final reads verify the requested types/values, both views and preservation of the invocation-header preference. This is not a transaction or an atomic directory lock; another administrator, GPO or filesystem writer can change state after a check.

`Applied`/`AlreadyCompliant` mean the machine policy and directory observations passed these checks. They do not prove transcript generation or access for another identity. `Failed` covers read/write problems, unsafe/unknown destination state and verification errors; `Overridden` covers later detected policy drift. `Skipped` includes dry runs and operator-declined changes. Exit 0 means no failed or overridden controls, including runs with skips; it is not a transcript-generation or CIS-wide compliance result.

For a completed `Applied` local-directory configuration, [transcription-recovery](transcription-recovery.md) provides reviewed typed restoration with durable receipts and explicit temporary-suspension consent. Failed/partial configuration runs and unsupported original values still require manual review.

If a later write fails, an earlier `OutputDirectory` write can remain. Review `before.jsonl`, the current policy and the authoritative GPO/MDM source. To recover, restore **only** `OutputDirectory` and `EnableTranscripting` from `Before.Policy[0].Machine`, preserving each original value's registry type; remove a value when its original `ValueExists` was false. If necessary, temporarily set `EnableTranscripting` to DWORD `0` while restoring the previous location, then restore its original value/type or absence last. Leave invocation-header and unrelated values untouched. Remove a newly created `Transcription` key only if it was originally absent and is still empty; do not delete a whole policy subtree or restore old ACLs over later changes. The journal contains policy paths/security information and should be protected as administrator recovery data.

## Evidence and limits

Transcript files are **text**, separate from PowerShell EVTX events **4103/4104**. Reports set `SigmaEvtxCredit=0` and contain no transcript event-ID claim. Enabling transcription does not automatically make an EVTX Sigma rule usable or add to reported Sigma coverage.

The mock suite covers typed values, shared views, idempotence, ordering, destination/policy races, denied reads/writes, partial failure, recovery journaling, header preservation and report limits. The Windows workflow targets disposable Server 2022/2025 runners under both WELA hosts (5.1 and 7). Its explicitly gated native test creates only owned private directories, saves original policy, configures transcription, launches fresh native Windows PowerShell 5.1 sessions (native/x86 where installed), and searches for benign markers in automatically produced transcript files. It restores exact original policy in `finally`, verifies restoration, and removes its generated files. If restoration fails, it fails the job and retains the private recovery evidence. PowerShell 7 is a test host, not a transcript-generation target.

Native CI passed on both Server 2022 and Server 2025 under Windows PowerShell 5.1 and PowerShell 7 in [run 35439090461](https://github.com/Yamato-Security/WELA/actions/runs/35439090461): 14 native assertions per OS/host combination, including fresh x64/x86 Windows PowerShell 5.1 transcript markers and verified restoration (56 native assertions total). Production/central validation still requires actual client, server, DC and service identities: test a benign new session, record the transcript and effective policy, verify unauthorized read/modify attempts fail, check collection and quotas/retention, and verify recovery. CI's local private folder does not satisfy the central authorization/ingestion acceptance criterion. Sysmon and external telemetry are out of scope.

Reviewed CIS references: [Windows 11 Enterprise v4.0.0, PDF pages 1286–1287](https://rayasec.com/wp-content/uploads/CIS-Benchmark/Microsoft-Windows-Desktop/CIS_Microsoft_Windows_11_Enterprise_Benchmark_v4.0.0.pdf#page=1286), [Windows Server 2022 v4.0.0, PDF pages 1029–1030](https://rayasec.com/wp-content/uploads/CIS-Benchmark/Microsoft-Windows-Server/CIS_Microsoft_Windows_Server_2022_Benchmark_v4.0.0.pdf#page=1029).

For a fixed child under the actual current account, see the optional [automatic transcription probe](transcript-probe.md). It verifies completed local automatic output without changing policy or granting EVTX/Sigma credit.
