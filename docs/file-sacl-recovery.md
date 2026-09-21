# Recover one selected leaf-file audit ACE

`file-sacl-recovery` removes one explicit ordinary audit ACE proven to have been added by a completed `targeted-sacl` operation. It supports one existing local leaf file, selected from the installed catalog with `Inheritance=None` and without child consent. Use elevated native 64-bit PowerShell on the original host. Registry keys, directories, descendants, inherited/object/callback ACE additions, arbitrary supplied ACEs and older or source-mismatched receipts require manual review.

This command changes only that file's SACL. It does not restore audit policy, rewrite its DACL, stop services, alter inheritance settings, or make an event-generation/Sigma readiness claim. Sysmon is out of scope. Preserve trusted original evidence; hashes detect changes and bind the reviewed selection but do not authenticate an untrusted receipt author.

## Required evidence and review

Retain all four files from the original public selected-target operation:

- Its original one-target `Plan` JSON, recorded while the row was `ChangeRequired`.
- The matching `<id>.pending.json` and `<id>.confirmed.json` under the original backup directory.
- The successful `Configure` results JSON, with its one row marked `Applied`.

The original before/after snapshots must prove exactly one new explicit ordinary audit ACE for the selected principal, rights and outcomes. Every previous ACE's bytes and count must remain; owner/group, DACL bytes, control flags, resource-manager control byte and SACL revision must agree, except that the original addition may have introduced the SACL-present flag. Neither an already-covered ACE nor any additional unexplained delta grants removal authority. Original snapshots are reconstructed from their binary descriptors and checked against their reported metadata.

The host/context, installed catalog and original selected-operation source hashes must still match. Recovery additionally records current helper/source hashes, actual elevated operator SID/groups and machine GUID, original input hashes, full current descriptor bytes and volume/file-index/creation identity. Current state must exactly match the confirmed addition. Input JSON is strict UTF-8, rejects duplicate properties and is limited to four MiB per file.

```powershell
.\WELA.ps1 file-sacl-recovery `
  -FileSaclRecoveryOriginalPlanPath C:\Evidence\selected-plan.json `
  -FileSaclRecoveryPendingPath C:\Evidence\receipts\sacl-<id>.pending.json `
  -FileSaclRecoveryConfirmedPath C:\Evidence\receipts\sacl-<id>.confirmed.json `
  -FileSaclRecoveryResultsPath C:\Evidence\selected-results.json `
  -FileSaclRecoveryOutputPath C:\Evidence\recovery-review
```

Review the new `plan.json`, especially `OriginalFiles`, `Operator`, `Expected`, `AddedAce` and `BeforeAddition`. Record its SHA-256 from the command result or `Get-FileHash`. The review directory must be new, outside the WELA installation, with an existing parent.

```powershell
$plan = 'C:\Evidence\recovery-review\plan.json'
$hash = (Get-FileHash $plan -Algorithm SHA256).Hash.ToLowerInvariant()
.\WELA.ps1 file-sacl-recovery -FileSaclRecoveryAction Restore `
  -FileSaclRecoveryPlanPath $plan -FileSaclRecoveryPlanHash $hash -DryRun

.\WELA.ps1 file-sacl-recovery -FileSaclRecoveryAction Restore `
  -FileSaclRecoveryPlanPath $plan -FileSaclRecoveryPlanHash $hash `
  -Auto -FileSaclRecoveryOutputPath C:\Evidence\recovery-result
```

`DryRun` rebuilds and compares the review from the original evidence and current host/file, then reports `WouldRemoveAddedAce`; it writes nothing. Actual restore requires `Auto` and a new private output directory outside the review directory. Both actions reject a modified or stale plan; rerunning an already completed plan is refused.

## Mutation and outcomes

Before mutation, `reviewed-plan.json` and `pending.json` are created exclusively, flushed to disk, reopened and hashed. Implementation, operator, host, original input files and reviewed plan are rechecked. The native helper holds a file handle without delete sharing, rejects directories and reparse files, verifies its final path and actual identity, and rereads the exact descriptor. It submits only `SACL_SECURITY_INFORMATION` to remove the unique proven ACE. Temporary `SeSecurityPrivilege` state is restored.

Afterwards WELA reads the held file and reopens the path, checks identity, unrelated ACE bytes/counts, SACL presence, revision when an ACL remains, owner/group, DACL, control flags and resource-manager control, then rechecks sources/evidence and reopens once more. Descriptor observations cover WinSDK-defined sections `0x1ff`; future sections are unobserved. Windows security-descriptor operations are not an atomic compare-and-swap against another administrator. Quiesce concurrent ACL writers; the guards detect observed drift, not an arbitrarily timed competing write.

`result.json` reports:

| Status | Meaning |
| --- | --- |
| `AddedAceRemoved` | One proven addition was removed and the bounded readback/preservation checks passed. |
| `Refused` | The operation failed before any native write attempt. |
| `WriteAttemptedUnverified` | A native write was attempted but complete final verification failed. Retain evidence and inspect manually. |

Removing the final audit ACE may leave an **empty or null present SACL** even if the historical descriptor had no SACL. Windows may retain `SACL_PRESENT` while returning no ACL pointer (`PresentNull`); this is accepted only when the removed ACE was the sole original ACE and all outside control/header fields still match. `SaclBefore` and `SaclAfter` record the observed representation and available ACL revision. This is an ACE-removal result, not a byte-for-byte restoration of the historical descriptor. `OriginalDescriptorBytesMatch` is only an observation; exact historical descriptor equality and original ACE ordering are not promised. Unrelated ACE bytes and counts are preserved. WELA does not automatically re-add the ACE after partial failure. No outcome grants rule-readiness credit.

## Validation and limits

`tests/FileSaclRecovery.Tests.ps1` covers strict input, source binding, durable exclusive output and action guards; separate CLI tests run real public process dispatch. Native descriptor tests exercise exact deltas and unsafe ACE/header/control changes. The explicitly gated Windows fixture runs on disposable Server 2022/2025 with Windows PowerShell 5.1 and PowerShell 7: it installs an owned one-file catalog only in a disposable checkout copy, obtains genuine public `Plan`/`Configure` receipts, then exercises public review/dry-run/removal/replay refusal, altered evidence/source and replacement file identity. Empty and unrelated-ACE cases retain their observed outside descriptor components. The fixture restores all 59 audit-policy masks and the exact typed precedence value/absence and deletes only its owned files.

This is not Windows 11, DC, ADCS, inherited directory recovery, distributed policy refresh or event/backend acceptance evidence. The original selected-target implementation files remain unchanged so the recovery feature itself does not invalidate their existing source hashes.

API contracts: [GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo), [SetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo), [RawSecurityDescriptor](https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.rawsecuritydescriptor).
