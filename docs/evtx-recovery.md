# Native EVTX export and recovery evidence

Related to #382. `evtx-recovery` exports one validated native Security 4688 probe to a new `.evtx` file, reopens it with the Windows event API and compares its original event fields. `Verify` can repeat that read under the intended reader's actual Windows session. Sysmon is excluded.

```powershell
# First collect a real fixed probe using existing, enabled audit prerequisites.
./WELA.ps1 native-validation -ProbeAction Run -ProbeOutputPath C:\Evidence\probe
# On that source host, export exactly the observed record and verify native readback.
./WELA.ps1 evtx-recovery -EvtxAction Export -EvtxProbePath C:\Evidence\probe -EvtxOutputPath C:\Evidence\archive
# Run under the intended reader account with access to the unchanged source bundle and EVTX.
./WELA.ps1 evtx-recovery -EvtxAction Verify -EvtxProbePath C:\Evidence\probe -EvtxArchivePath C:\Evidence\archive\probe.evtx -EvtxOutputPath C:\Evidence\readback
```

`Verify` is the default. The command changes no Windows policy, log settings, retention or permissions on existing evidence. New output directories restrict inherited access to the current user, SYSTEM and local Administrators; any transfer/access arrangement for another reader is an operator task. Local fixed-drive paths only; no network/device paths, alternate streams, reparse traversal, overwrites or output inside the input bundle. Relative paths follow PowerShell's current location.

The importer requires the exact five native-probe files, four matching hashes, strict JSON, consistent embedded metadata, all 59 typed audit masks, valid native process/event identities and unchanged source prerequisites. Imported evidence is operator supplied; hashes prove consistency, not authenticity. Export compares the live source host and policy context to the original probe and verifies the actual Security record before copying it. The exported file is reopened even when Windows reports a successful export: an empty EVTX is not success.

The archive stays open without write/delete sharing during hashing and native readback. Exactly one event must match the original System and EventData semantics. XML namespace/attribute order and optional RenderingInfo are handled without ignoring original fields. Empty, corrupt, denied, duplicate or changed records remain `Unverified`, as do reader/host/source changes. The report records actual archive bytes/hash, reader SID/groups/session identity, host context, source identity, query, timestamps and recovered raw XML. Readback observes the current token, not hypothetical access by a supplied SID.

`NativeEventRecovered` proves only that this recorded reader recovered this one event at the observation time. It does not establish completeness, eighteen-month retention, rollover behavior, storage capacity, other-principal access, disaster recovery or Sigma readiness. It does not archive localized message resources or clear the source log. The new archive is a probe artifact, not a full-log backup.

Focused fixtures exercise source/event tampering, empty/duplicate/corrupt/denied readback, drift, paths and CLI guards. Explicitly gated disposable Server 2022/2025 tests under PowerShell 5.1/7 collect a genuine 4688 event, export/reopen it, independently verify it, reject an actual empty EVTX and restore all temporary audit settings. Windows 11/DC/ADCS, alternate-reader and long-term recovery exercises remain deployment checks.

Implementation references: [Microsoft EventLogSession.ExportLog](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogsession.exportlog) selects events without message resources; [EvtExportLog](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtexportlog) requires a new target and can create a header-only file for an empty query.
