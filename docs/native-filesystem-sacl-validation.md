# Public filesystem SACL lifecycle validation

The `Native public filesystem SACL lifecycle` workflow validates the public `targeted-sacl` command against its real built-in per-user Signal directory definition. It runs on disposable Server 2022/2025 hosts with Windows PowerShell 5.1 and PowerShell 7. It uses an owned redirected folder, its existing ordinary descendants and a protected subtree, then runs the public `file-access-probe` against one inherited leaf SACL.

## Owned fixture boundary

The test creates a fresh private directory on the system volume, a newly saved hive mounted under a nonce-derived synthetic SID, and a matching new `ProfileList` entry. The entry contains only its ownership marker and typed `ProfileImagePath`. Its loaded hive supplies a redirected `AppData` known-folder value. The ordinary catalog must independently discover exactly that SID's Signal directory and classify it `Redirected`; no alternate catalog, arbitrary target switch or mocked resolver supplies selection authority.

The synthetic SID is a fixture identity, not a created Windows account or proof of another user's effective access. The read worker uses the actual elevated runner account. Existing users, offline hives and system catalog targets are not modified. Profile registration, hive loading, initial unrelated ACE/protection setup and temporary audit policy are test-only operations; public WELA commands do not perform them.

The test alone prepares File System success/failure auditing and typed advanced-audit precedence. It requires a complete observation of all 59 masks, the original full process token and the complete bounded `ProfileList` key/value inventory. Profile values retain their registry types and unexpanded data. The test never restores a whole saved system registry tree over current state.

## Public operations and retained proof

The fixture exercises this sequence with bounded, separately launched public WELA processes:

1. Discover the actual redirected catalog target. Plan without child consent must block inheritance.
2. Plan with explicit child consent must capture the exact parent and all four existing descendants: one ordinary directory/leaf pair and one protected directory/leaf pair.
3. DryRun must leave every descriptor unchanged and create no recovery directory.
4. Create one owned unreviewed child. Configure using the earlier plan must refuse before journaling or writing. Remove that fixture child and generate a fresh plan.
5. Configure the fresh selection. A successful result must contain one `Applied` row and matching distinct Pending, Confirmed and descendant-observation records.
6. Independently read the parent and children. Exactly one required root ACE is added; its unrelated ACE, owner, group, DACL and other observed descriptor components remain. Two ordinary descendants show the inherited ACE, while both protected descendants retain their original security.
7. A fresh Plan/Configure reports `AlreadyCompliant`, adds no duplicate ACE or receipt, and preserves the complete observed tree.
8. Public file-probe Plan/Run on the ordinary leaf must observe the existing inherited ReadData SACL and exactly one attributable local Security 4663. The protected leaf must remain uncovered and its read probe must refuse before a read operation.

The probe retains raw XML and binds the actual worker PID, handle, subject SID/logon, native file identity/path, access mask and measured one-byte-read/held-identity-readback phase. It reads exactly one byte and retains no file content. Only the fixture hashes its known harmless files to check byte preservation. The public configuration still reports `GenerationReadiness=Conditional` and `UsableRuleCredit=0`; the probe grants no Sigma credit.

Review `fresh-plan.json`, `results.json`, `journal/`, the independent before/after/final descendant snapshots, `probe-result.json`, `probe/event.xml`, `cleanup.json` and `artifact-hashes.json` together. A process exit or printed status alone is insufficient. A failed run can retain partial evidence and is not a successful lifecycle result.

## Cleanup and limits

Cleanup restores the original selected audit mask and exact typed precedence, then independently compares every original audit mask, full token, `ProfileList` inventory/data and loaded-hive names. The ProfileList adapter removes only its exact unchanged two-value, childless, marker-owned entry. Changed ownership or partial setup prevents unproven deletion and is retained as a cleanup error. The owned hive is unloaded, its original seed removed, and the private hive files/target tree removed only after profile and hive restoration is verified. Each independent verification is guarded so one failure does not hide other cleanup observations. Registry parent last-write metadata is not restored or claimed unchanged.

This proves the observed fixture cases on the tested builds. It does not establish arbitrary redirected-user access, remote shares, offline profiles, future children, an atomic tree transaction, Windows 11, domain/DC/CA behavior, forwarding, retention or backend Sigma execution. No receipt authorizes removing inherited ACEs from production descendants. The selected command's existing concurrency and partial-write limits still apply.

The system-volume fixture is deliberate: some hosted data volumes emit the Removable Storage task even when `DriveInfo` reports Fixed. The existing probe accepts File System task 12800 only. Neither a protected branch nor another volume receives event credit from the successful ordinary leaf.

See [selected SACL configuration](selected-sacl-configuration.md), [file-access probe](file-access-probe.md) and the separate [public registry lifecycle](native-registry-sacl-validation.md). Microsoft documents [SetSecurityInfo inheritance behavior](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo) and the [4663 access-use event fields](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663).
