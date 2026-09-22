# Custom advanced audit profiles

`-ProfileFile` selects an operator-owned JSON file for `profiles`, `plan`,
`audit-settings` (also `audit`) and `configure`. Built-in files and legacy baseline
outputs are unchanged. Custom profiles cover advanced Security audit policy and
its precedence prerequisite only. Sysmon is excluded; channel settings, SACL
writes, command-line capture, forwarding and other native settings retain their
separate commands. A matching configuration does not establish Sigma readiness.

```powershell
./WELA.ps1 profiles -ProfileFile config/custom-audit-profile.example.json
./WELA.ps1 plan -Profile custom-example -ProfileFile config/custom-audit-profile.example.json -Role Client -Build 26100 -PlanPath custom-plan.json
./WELA.ps1 audit-settings -Profile custom-example -ProfileFile C:\Policy\organization.json -PlanPath custom-audit.json
./WELA.ps1 configure -Profile custom-example -ProfileFile C:\Policy\organization.json -DryRun -ResultsPath preview.json
./WELA.ps1 configure -Profile custom-example -ProfileFile C:\Policy\organization.json -BackupPath C:\Policy\new-recovery-directory -ResultsPath result.json
```

Copy and review the example before configuration. Its placeholder source URL is
not a real standard. The example requests minimum Process Creation Success,
exact Process Termination Success, optional File System Success/Failure, and
preserves Detailed File Share. Exact settings may remove existing auditing;
minimum settings preserve extra enabled flags. File System remains unchanged
unless `-IncludeOptional` is selected and requires matching object SACLs for useful
events. Every omitted subcategory remains explicitly unchanged or role-inapplicable.

`-Profile` is mandatory except when listing the file. The selected ID must belong
to that file; WELA does not fall back to a built-in profile or merge definitions.
Built-in IDs cannot be redefined. `-Baseline` and unrelated command options cannot
be combined with `-ProfileFile`. Supply both role/build for offline plans or omit
both for native detection. Explicit custom applicability is operator-declared;
it is not a claim that WELA or Microsoft tested that build. Live application still
requires the actual role/build to match and refuses unreadable current state.

## File format

Use UTF-8 strict JSON, at most 1 MiB and 20 nesting levels, with:

- `schemaVersion: 1` and `kind: "WelaCustomAuditProfiles"`.
- `catalog`: 1–59 references, each containing exact canonical `id` (subcategory
  name), `guid` and `category`. List every control used anywhere in the file.
  GUID casing is immaterial; names/category spelling must be exact. The full
  authoritative catalog supplies supported roles and prerequisites: custom files
  cannot replace those fields or introduce arbitrary GUIDs.
- `sources`: a nonempty object keyed by lowercase source IDs. Each source requires
  nonempty `title`, `version` and an absolute HTTPS `url`. URLs are references only;
  WELA never fetches them. Source identity remains operator-declared.
- `profiles`: 1–128 objects with unique lowercase IDs, `version`, `sourceIds`,
  `omitted: "unchanged"`, `scope: "advanced-audit-policy-only"`, `appliesTo`,
  `controls`, and `roleOverrides`. Optional `note` is text; optional `referenceOnly`
  is boolean and prevents configuration when true.

Each applicability range declares `roles` and integer `minBuild`/`maxBuild` within
1–999999. Roles are Client, MemberServer, DomainController and ADCS (a member-server
CA). Combined DC/CA detection remains unsupported. Each `controls` entry uses a
catalog name and `{ "mode": ..., "mask": ... }`; source IDs, evidence and notes can
also be attached to a control. Role overrides use the same control schema.

| Mode | Mask | Behavior |
|---|---|---|
| exact | Integer 0–3 | Exact required success/failure flags; may remove existing flags |
| minimum | Integer 0–3 | Enable only required flags, preserving additional auditing |
| optional | Integer 0–3 | Preserve unless `-IncludeOptional`, then apply the exact mask |
| unchanged | Omitted | Preserve current policy |
| not-configured | Omitted | Preserve effective policy; does not remove GPO/MDM configuration |
| not-applicable | Omitted | Skip this control |

Success is 1, Failure is 2, both is 3, neither is 0. Duplicate/case-colliding JSON
properties, duplicated IDs/GUIDs, unknown fields, invalid source references,
undeclared controls, coercible string/boolean masks and unsupported types are
rejected. Input is parsed as data; strings containing script syntax are never
executed. Executable hooks and custom command strings are not supported.
JavaScript extensions such as single-quoted or unquoted property names are also
rejected before duplicate-key checks; they cannot hide a second audit mask.

For canonical identifiers, inspect `config/audit_profiles.json` or run:

```powershell
Import-Module ./modules/AuditProfiles.psm1
(Import-WelaAuditProfiles).catalog | Select-Object id, guid, category, roles, prerequisites
```

## Verification and recovery

Strict file validation runs before host reads. An explicitly supplied unsupported
role/build is rejected at that stage; otherwise native detection supplies context.
Plans and results record the exact selected-file SHA-256, canonical-catalog
SHA-256, profile version and declared sources. Output/backup paths cannot equal the
selected input or canonical catalog. No built-in profile file is written.
For custom profiles, `-ResultsPath` and `-PlanPath` must name distinct **new local
files under existing directories**. Existing outputs are preserved, including
hard-link or symlink aliases of an input. Reparse-point directory ancestry is
refused, and final output uses `CreateNew` rather than overwriting a file created
after the initial check. Choose fresh names for repeated runs. Both successful
and failed configuration results can be written without altering the input;
the result's source fingerprint describes the policy that was assessed.

The shared configuration engine checks file fingerprints and actual role/build
before each control, after confirmation/journaling but before each write, and at
read-back/final verification. Precedence must be verified before dependent audit
writes. Every pre-change journal entry records input provenance. Minimum writes
only enable required native flags, and verification accepts compliant supersets.
Changed, deleted or unreadable input stops subsequent writes and reports failure;
already applied changes remain recorded for recovery. Checks are observations,
not atomic protection against a privileged writer replacing files between checks.
Keep the policy directory controlled during the operation.

Review `before.jsonl` and restore only the recorded preceding precedence value/type
and audit flags through your approved recovery process. WELA does not automatically
undo partially applied changes, restore a GPO, or invoke policy refresh. Re-run the
assessment after GPO/MDM refresh to verify effective state.

Tests exercise malformed files, preservation modes, validation ordering, mocked
writes, prompt-time file changes and final drift. Windows CI also exercises the actual public Plan, DryRun, Configure and Audit
commands on disposable Server 2022/2025 hosts with PowerShell 5.1/7. A fixture-owned
custom file selects four canonical controls: minimum and exact masks, an explicit
optional control, and Not Configured preservation. Tests compare all 59 masks,
typed precedence, source fingerprints, native channels and original journals,
then verify exact fixture restoration. Invalid role selection is refused before
configuration, and repeated configuration makes no further native change.
These are hosted standalone servers classified by the shared profile engine as
MemberServer; no domain join or GPO refresh is simulated. Configuration and
benign event/backend acceptance on Windows 11, domain-joined servers, DC and AD CS labs remain separate;
no clean-install or detection-coverage claim is made.
