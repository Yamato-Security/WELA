# Public registry SACL lifecycle acceptance

The `Native public registry SACL lifecycle` workflow tests the existing public `targeted-sacl` command on disposable GitHub-hosted Windows Server 2022 and 2025 runners, each with native Windows PowerShell 5.1 and PowerShell 7. It is an acceptance fixture, not a new configuration command. Native job results and retained artifacts must be reviewed before claiming a particular matrix passed.

## Owned target and public lifecycle

The fixture creates a nonce-marked seed key below its own HKCU, saves it to a new private file, and loads that file under a new synthetic SID below HKU. It never loads an existing user's offline hive or modifies a catalog system key. Existing backup/restore privileges are enabled only around the native save/load/unload calls and their prior attributes are restored. Impersonation and name collisions are refused. The unchanged public catalog resolves the loaded SID's RunOnce definition from `asd-native-2021-10`; the missing ProfileList metadata remains explicit in user-inventory diagnostics.

Only the fixture prepares typed audit precedence and the Registry success/failure subcategory. It creates a sentinel DWORD and a distinct SYSTEM QueryValue success audit ACE before exercising the selected target through actual `WELA.ps1` processes:

- Plan with missing inheritance consent is blocked and Configure refuses before creating a journal.
- A reviewed Plan captures the exact selected SID/path, native descriptor and complete empty descendant inventory.
- DryRun leaves the descriptor unchanged and creates no write journal.
- Configure appends exactly the reviewed audit ACE. Independent native readback verifies original owner/group/DACL/control flags, original binary audit ACEs and the unrelated typed value. Pending, Confirmed and descendant-observation receipts agree with the independent observations.
- Replaying the stale plan fails before another journal. A fresh plan and Configure report `AlreadyCompliant`, preserve exact state and write no mutation receipts.
- Removing the prerequisite Registry audit bits makes planning blocked and Configure fail before journaling; the public command does not enable auditing.

The chosen RunOnce target has no child keys. Populated and protected subtree behavior remains covered separately by the existing descendant fixture. This fixture does not establish production-tree, redirected-user, DC/CA or future-child behavior.

## One actual registry event

After public Configure succeeds, the fixture records a native Security event watermark, then performs exactly one `RegSetValueExW` call to create a fresh nonce REG_SZ. It reads the value's type and exact bytes back on that same native handle. Precise UTC receipts separately record write start, return and completion of this measured write/readback phase; no timestamp padding is added.

A bounded native Security query must return exactly one matching 4657 from the observed phase, with the exact provider/version/task/success keyword, computer, newer record ID, subject SID/logon ID, process ID/executable, raw registry handle, native object path, value name, creation operation, REG_SZ type and nonce value. Event candidates, exact XML, operation receipt and artifact hashes are retained. Portable negative fixtures reject wrong attribution, old/out-of-window records, duplicate fields and DTD-bearing XML. A missing or ambiguous event fails acceptance; it does not relax attribution.

This is evidence for one local registry **value** creation under the fixture's prepared policy. It does not prove all registry operations, production persistence, downstream forwarding, collector access or Sigma execution. Public reports retain `GenerationReadiness=Conditional` and `UsableRuleCredit=0`.

## Cleanup and evidence

Cleanup runs even after an assertion fails. It restores the original selected Registry audit mask and original precedence type/value or absence, then compares every one of the 59 audit masks. It checks the entire primary-token groups/privilege snapshot, unloads only the marker-verified owned hive, removes only its exact unchanged seed, and compares the complete original HKU mount inventory. The private backing files are deleted only after unload and inventory verification. Failure to restore or unload fails the job and remains explicit in `cleanup.json`.

The artifact retains public reports/journals, independent before/after descriptors, exact event XML, native operation and cleanup evidence, and SHA-256 hashes. Successful cleanup retains no backing hive file. This test-only helper is not imported by WELA and is not packaged as a product hive-management feature.

Primary references: Microsoft [RegSaveKeyExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsavekeyexw), [RegLoadKeyW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regloadkeyw), [RegUnLoadKeyW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regunloadkeyw), and [Security event 4657](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4657).
