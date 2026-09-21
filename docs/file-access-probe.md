# One-byte local file access probe

`file-access-probe` checks whether one explicit read of one existing file produces an attributable local Security 4663 event. Plan observes prerequisites without reading file data. Run opens the same selected leaf in a fixed worker, reads exactly one byte once, clears that buffer and retains no file contents. It changes no audit policy, ACL, service, channel setting or file data. A native read can update access metadata and can trigger existing monitoring.

Run elevated in native 64-bit Windows PowerShell 5.1 or PowerShell 7. Select an ordinary, nonempty file on a fixed local drive using its exact absolute DOS path (at most 240 characters). UNC/device input paths, alternate streams, wildcards, reparse components, multiple hard links, EFS, offline/recall files and directories are refused. The token must already hold the security privilege needed to inspect the SACL; observation enables that existing privilege only around handle acquisition and restores its prior state before the data read. No privilege is granted and backup semantics are not used.

The File System subcategory must already include Success, `SCENoApplyLegacyAuditPolicy` must be typed DWORD 1, and the enabled Security channel must be readable. One existing ordinary success ReadData audit ACE must apply directly to the user SID or an enabled, non-deny-only group. Inherit-only and conditional/callback ACEs cannot establish this prerequisite. EventLog, Winmgmt and RpcSs must already be running. This command does not install a SACL or repair prerequisites.

```powershell
.\WELA.ps1 file-access-probe -FileProbePath C:\Audit\existing-file.txt
.\WELA.ps1 file-access-probe -FileProbeAction Run `
  -FileProbePath C:\Audit\existing-file.txt `
  -FileProbeOutputPath C:\Evidence\new-file-probe `
  -FileProbeTimeoutSeconds 15
```

Run requires a fresh private evidence directory outside the code tree. Only dedicated options are accepted; no `-Auto`, `-DryRun`, generic `-WhatIf` or extra positional arguments. `FileProbeTimeoutSeconds` accepts 1–30 seconds for polling after the worker; worker execution has a separate 20-second limit. Native query work and cleanup add elapsed time.

The request binds actual host/build/MachineGuid, engine and implementation hashes, token groups and privileges, all effective audit masks, precedence, Security configuration and full selected-file metadata/security. A held existing-file handle prevents concurrent write/delete opens. Volume/file ID, creation and last-write times, size, attributes, link count and full current SDK security descriptor must agree before and after the operation. Both DOS and NT volume names are observed from that same handle and bound to this identity. Path comparison is case-insensitive; other volume names or paths are not inferred or accepted.

Before launch, the parent writes and flushes `before.json` and `intent.json`. The worker inherits the existing execution policy without an override; a blocked worker remains unverified with its prior intent retained. The fixed worker independently rebuilds the request state, verifies its primary token, performs one native `ReadFile` call requesting one byte and returns a receipt with exact PID, handle and precise start/completion timestamps. The parent retains `operation.json`, the original matching `event.xml`, `after.json` and their SHA-256 hashes in `manifest.json`. These artifacts contain file paths, SIDs, security descriptors and audit context, but no target contents or target-content hashes. The manifest is not self-hashed.

Success requires exactly one fresh version-1 Security 4663 from the expected provider, computer, user SID/logon ID, worker PID/executable, native handle, selected DOS or NT path and ReadData mask/access token. Event time must fall within the actual native read interval, with no padding. The query stops at 256 events and bounds individual XML size; hitting a cap, missing/duplicate evidence, drift, changed reader context or failed persistence prevents verified success. The final Security record boundary must not move backwards.

`PrerequisitesObserved` (Plan) and `FileReadObserved` (Run) exit 0. `Unverified` exits 1 and explains the observed gap. A stopped or failed worker may already have attempted the read; durable intent alone does not prove completion. An interrupted process may leave only partial evidence, and a manifest-write failure fails outward while earlier receipts remain. Inspect retained artifacts before deciding whether to run another probe in a different fresh directory.

This is evidence for that one current-token local ReadData success. It does not prove Failure auditing, other rights/users/files, child inheritance, forwarded delivery, backend parsing, Sigma readiness or general detection coverage. Security 4663 has no Failure variant. No Sigma/EVTX coverage points are added.

The disposable Windows fixture owns its files and evidence directories, explicitly establishes the test SACL/policy, exercises the public Plan/Run path twice, verifies all artifact hashes and unchanged file content/security, tests missing-SACL/policy and file-replacement refusals, then restores all effective audit masks, typed precedence and token state. It removes only its owned target directory and retains cleanup evidence. Server 2022/2025 and PowerShell 5.1/7 run independently; these fixture changes are not product behavior.

Microsoft references: [4663 event semantics and fields](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663), [ReadFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile), and [same-handle DOS/NT path observation](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew).
