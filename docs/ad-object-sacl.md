# AD directory object auditing

`ad-object-sacl` is a dedicated opt-in command for **built-in AD DS SACL auditing**. It requires Windows PowerShell 5.1 or PowerShell 7 on Windows, an explicit DC FQDN, and credentials permitted to read the complete security descriptors and update SACLs on the selected objects. Use an account with the necessary directory security privilege; the command does not grant privileges or modify authorization. It does not use the local file/registry `configure-sacl` targets.

```powershell
# Audit/plan read directory state without changing it. Export exact DNs and ACEs.
./WELA.ps1 ad-object-sacl -AdServer dc01.example.test -AdSaclAction Plan `
  -AdSaclProfile MdiDomain -ResultsPath ad-plan.json

# Configure is explicit. DryRun performs the same reads, without AD writes or backups.
./WELA.ps1 ad-object-sacl -AdServer dc01.example.test -AdSaclAction Configure `
  -AdSaclProfile MdiDomain -DryRun -ResultsPath ad-preview.json
./WELA.ps1 ad-object-sacl -AdServer dc01.example.test -AdSaclAction Configure `
  -AdSaclProfile MdiDomain -Auto -BackupPath .\new-ad-backup -ResultsPath ad-result.json

# Current/former Exchange configuration is a separate forest-wide choice.
./WELA.ps1 ad-object-sacl -AdServer dc01.example.test -AdSaclAction Plan `
  -AdSaclProfile MdiConfiguration -ResultsPath exchange-plan.json

# PKI objects are explicitly selected, not every object in the Configuration partition.
./WELA.ps1 ad-object-sacl -AdServer dc01.example.test -AdSaclAction Plan `
  -AdSaclProfile PkiObjects `
  -AdObjectDn 'CN=LabTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=test' `
  -ResultsPath pki-plan.json
```

Multiple profiles or PKI DNs can be passed as PowerShell arrays. `-Profile` and `-Baseline` select Security audit policy and are rejected by this command. The AD-specific parameters are rejected on other commands. There is no implicit domain discovery: aliases, LDAP URLs, ports, and a RootDSE host different from `-AdServer` are refused. All requests use one connection to that DC with Negotiate authentication, LDAP signing/sealing, and referral chasing disabled. AD LDS and unknown DC write capability are refused. RODCs can be read; required changes are reported `Blocked`.

## Exact profiles

All ACEs use **Everyone (`S-1-1-0`)**. An empty object GUID is `00000000-0000-0000-0000-000000000000`; it does not restrict the ACE to one property. Plans export the target DN, class, SID, decimal rights mask, named rights, audit outcomes, ACE flags, object GUID, inherited class GUID, and inheritance. Schema GUIDs are checked against the same DC before planning writes.

`MdiDomain` targets RootDSE `defaultNamingContext`. Each ACE audits **Success**, applies to **descendants only** of the listed class, and has ACE flags `74` (`0x4A`: Success, ContainerInherit, InheritOnly), empty object GUID and the following inherited class GUID. The precise masks follow Microsoft's [readiness script at commit 730dad6](https://github.com/microsoft/Microsoft-Defender-for-Identity/blob/730dad6870154279b6c41009c9ebab84ffa24689/Test-MdiReadiness/Test-MdiReadiness.ps1), rather than approximating the UI's “Full control minus read” instructions.

| Descendant class | Mask | Inherited class GUID |
| --- | ---: | --- |
| user | 852331 (`0xD016B`) | bf967aba-0de6-11d0-a285-00aa003049e2 |
| group | 852331 (`0xD016B`) | bf967a9c-0de6-11d0-a285-00aa003049e2 |
| computer | 852331 (`0xD016B`) | bf967a86-0de6-11d0-a285-00aa003049e2 |
| msDS-ManagedServiceAccount | 852331 (`0xD016B`) | ce206244-5827-4a86-ba1c-1c0c386c1b64 |
| msDS-GroupManagedServiceAccount | 852075 (`0xD006B`) | 7b8b558a-93a5-4af7-adca-c017e67f1057 |
| msDS-DelegatedManagedServiceAccount | 852075 (`0xD006B`) | 0feb936f-47b3-49f2-9386-1dedc2c23765 |

Both masks include CreateChild, DeleteChild, Self, WriteProperty, DeleteTree, Delete, WriteDacl and WriteOwner. `852331` additionally includes ExtendedRight. dMSA is omitted, with a diagnostic, unless its schema class exists and a domain DC computer reports a version at least `10.0 (26100)`. This follows [MDI's Server 2025 domain condition](https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection#configure-auditing-on-domain-objects). Missing mandatory schema classes or unreadable/unknown applicability produce `Unknown`, not an assumed audit configuration. Protected child SACLs and inheritance propagation are not established by a root ACE read-back.

`MdiConfiguration` targets RootDSE `configurationNamingContext`, with **WriteProperty (`32`, `0x20`), Success and Failure**, **this object and all descendants**, flags `194` (`0xC2`), and both GUIDs empty. Microsoft's [Configuration container guidance](https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection#configure-auditing-on-the-configuration-container) is conditional on current or former Exchange deployments. WELA checks for an `msExchOrganizationContainer`; no matching object produces `NotApplicable`. If all historical Exchange configuration was removed, inspect that history manually: absence does not prove Exchange never existed. Configuration is replicated forest-wide; this operation is not scoped to one domain's users.

`PkiObjects` is a **WELA targeted profile**, not a claim that MDI prescribes a PKI SACL baseline. Each explicitly selected object gets a Success-only, **this-object-only** ACE: **WriteProperty, Delete, WriteDacl and WriteOwner (`852000`, `0xD0020`)**, flags `64` (`0x40`), both GUIDs empty. It accepts only these existing objects under this connection's Configuration naming context:

| Object class | Allowed container | Schema class GUID (validated, not placed in the direct-object ACE) |
| --- | --- | --- |
| pKICertificateTemplate | `CN=Certificate Templates,CN=Public Key Services,CN=Services,<ConfigurationDN>` | e5209ca2-3bba-11d2-90cc-00c04fd91ab1 |
| pKIEnrollmentService | `CN=Enrollment Services,CN=Public Key Services,CN=Services,<ConfigurationDN>` | ee4aa692-3bba-11d2-90cc-00c04fd91ab1 |

See Microsoft's [certificate template schema](https://learn.microsoft.com/en-us/windows/win32/adschema/c-pkicertificatetemplate) and [enrollment service schema](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/208d42e8-1932-4767-87c5-b8511991e69b). WriteProperty covers changes such as template attributes and an enrollment service's published `certificateTemplates` list; object creation, child objects, enrollment access rights and CA `AuditFilter` are separate. No security enforcement, enrollment permissions, CA settings, DACLs or owners are changed.

PKI parent membership is proven by a one-level LDAP lookup under the exact approved container using the target's binary object GUID. A matching textual DN suffix, including an escaped comma in an object's name, cannot establish this membership.

## Verification, concurrency and recovery

The command reads owner, group, DACL and SACL together using the critical [LDAP security descriptor flags control](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3888c2b7-35b9-45b7-afeb-b772aa932dd0). A missing object, incomplete descriptor or permission failure is an error. It records the original complete SDDL and binary descriptor, object GUID, same-DC `uSNChanged`, target DN and requested ACEs in `before.jsonl`. A separate `ad-sacl-*.json` receipt records the exact missing ACE additions and expected descriptor **before** the write. Keep these files private and treat receipts as trusted administrator input; they contain directory security configuration.

Receipts initially have `ReceiptStatus: Pending`, which never authorizes automatic rollback. Only after the LDAP write succeeds and a fresh read verifies the original security information and requested ACEs does WELA persist `Confirmed`, the confirmation time and observed state. Confirmation replaces the intent file while retaining its `.pending` backup. A failed/stale request, failed read-back, interruption or unpersisted confirmation requires manual recovery review; another writer's later matching ACEs do not turn an unconfirmed intention into WELA-owned changes.

Existing ACEs are retained byte-for-byte. A same-scope ACE with a superset of the rights/outcomes already satisfies the request; WELA adds only missing audit ACEs. After the prompt and durable journal, WELA rereads the same DC's object GUID, USN and complete descriptor and refuses a changed object. The LDAP modify uses a **critical SACL-only** control, preserving owner/group/DACL on the server. Read-back verifies every original ACE, non-SACL security information and requested auditing; a final read detects later drift. Microsoft documents that [`uSNChanged` is local to a DC](https://learn.microsoft.com/en-us/windows/win32/adschema/a-usnchanged), so the command never substitutes another DC for these checks.

**Use an exclusive maintenance window for SACL changes.** The immediate comparison is not an atomic compare-and-swap: a concurrent writer in the final read/write window can still lose a SACL update. WELA does not claim LDAP transaction protection, lock other writers, or automatically restore a whole descriptor after an uncertain result. Stop other SACL editors/automation, review failures against the journal and current descriptor, and verify again after inheritance/replication have settled.

```powershell
# Remove additions from one trusted receipt, first as a dry run.
./WELA.ps1 ad-object-sacl -AdServer dc01.example.test -AdSaclAction Rollback `
  -AdReceiptPath .\new-ad-backup\ad-sacl-RECEIPT-ID.json -DryRun
./WELA.ps1 ad-object-sacl -AdServer dc01.example.test -AdSaclAction Rollback `
  -AdReceiptPath .\new-ad-backup\ad-sacl-RECEIPT-ID.json -Auto `
  -BackupPath .\new-rollback-backup -ResultsPath rollback-result.json
```

Rollback requires a confirmed receipt, checks the DC and object identity, validates that the receipt's expected SACL contains precisely the recorded additions plus the old ACEs, and requires the current SACL to match that expected sequence. It removes only those exact additions, using the current descriptor and a SACL-only write; it never restores old owner/group/DACL data. Repeated rollback is idempotent. Reordered/merged ACEs or any intervening SACL edit make automatic ownership ambiguous and are refused. Pending receipts are refused even if current ACEs match the intended additions. If automatic rollback is refused, compare the original SDDL/ACE bytes, receipt additions and current SACL on the exact DC, identify additions manually, remove only those demonstrably attributable to this run, and preserve all unrelated current entries. Do not restore the complete saved SDDL over later changes.

`SaclConfigured`/`Applied`/`AlreadyCompliant` refer to the **selected object's SACL**. `ChangeRequired`, `NotApplicable`, `Unknown`, `Blocked`, runner `Skipped`, `Failed` and `Overridden` remain distinct. Exit 0 means no read/write/verification failures; dry runs and skipped requests do not establish configuration. No Sigma rule uplift is claimed.

## Required isolated-DC evidence before closing issue #371

`AuditPolicyPrerequisites` reports **Unknown** separately: this LDAP command neither reads nor configures the DC's effective audit policy. Verify Directory Service Access Success (and Failure for Configuration failure auditing), GUID `0cce923b-69ae-11d9-bed3-505054503030`, and Directory Service Changes Success, GUID `0cce923c-69ae-11d9-bed3-505054503030`, on each DC that will process test operations. Check GPO precedence and effective results; enabling a policy alone does not supply an object SACL. [Event 5136 requires matching object auditing and records the modified attribute on a DC](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136).

The automated tests use mock directory responses, in-memory Windows security descriptors and captured LDAP requests. They **never bind to or modify live AD**. Windows PowerShell 5.1 and PowerShell 7 CI validate native construction, preservation, idempotency, conservative rollback and the shared runner. Live Windows/DC validation has not been performed by this change.

For completion, use isolated patched DC snapshots and dedicated test accounts, groups, computers, templates and enrollment service objects. Record DC build, forest/domain, before/after SDDL, effective audit policy and WELA JSON. Make a benign attribute change on each selected object through the exact DC, then capture matching Security **4662** and **5136** XML, including computer, object DN/GUID, subject, access/property and attribute fields. Inspect inherited ACEs on each descendant class and protected objects; verify other DCs after replication. For certificate template or publication-list changes, collect the event from the **DC processing the AD change**, not automatically from the CA. Validate central ingestion, rerun for idempotency, exercise rollback and verify unrelated authorization and audit entries remain. No generated-event, replication, retention or ingestion guarantee is made here. Sysmon and external telemetry are out of scope.
