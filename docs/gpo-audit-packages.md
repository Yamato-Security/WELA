# GPO audit-policy deployment packages

`gpo-package` builds reviewable **offline components** from WELA's shared advanced audit-policy profiles. It does not generate a GPO backup, create/import a domain GPO, configure local policy or run LGPO. `Plan` is the default. The target role/build is explicitly declared by the operator; the exporter never assumes the machine running WELA is the deployment target.

```powershell
./WELA.ps1 gpo-package -GpoProfile wela-2.2.0 -Role Client -Build 26100
./WELA.ps1 gpo-package -GpoAction Export -GpoProfile wela-2.2.0 `
  -Role Client -Build 26100 -GpoOutputPath .\audit-components -DryRun
./WELA.ps1 gpo-package -GpoAction Export -GpoProfile wela-2.2.0 `
  -Role Client -Build 26100 -GpoOutputPath .\audit-components
./WELA.ps1 gpo-package -GpoAction Verify -GpoOutputPath .\audit-components

# A source minimum may need an explicit expansion to fit exact GPO semantics.
./WELA.ps1 gpo-package -GpoAction Export `
  -GpoProfile microsoft-wef-reviewed-2026-09 -Role MemberServer -Build 20348 `
  -GpoMinimumMode PromoteToBoth -GpoOutputPath .\wef-audit-components
```

Plan/Export require `-GpoProfile`, `-Role` and `-Build`, validated against the bundled profile's applicability. `-IncludeOptional` includes optional entries. Verify takes only its existing package path and reads context from the manifest; no context overrides are accepted. Use the returned PowerShell object's `Plan.Controls`/`Plan.Blockers` to inspect a plan. Export includes JSON and Markdown, so `-ResultsPath` and unrelated configuration/backup/profile options are rejected. `-DryRun` is supported only for Export and creates no files or directories. GPO-only parameters are rejected before unrelated profile command dispatch.

## Components and semantics

| File | Content |
| --- | --- |
| `audit.csv` | UTF-8 without BOM, CRLF, documented seven-column header; System subcategory GUIDs with exact positive values 1/2/3 only |
| `GptTmpl.inf` | UTF-16LE with BOM; only `SCENoApplyLegacyAuditPolicy=1` as a DWORD security-template registry value |
| `manifest.json` | Profile/version/hash, declared role/build, source provenance, all control dispositions, hashes/lengths/encodings and scope limits |
| `review.md` | Full control list, exported and omitted settings, minimum expansions, prerequisites and source references |
| `deployment.md` | Supported genuine-GPO preparation, reviewed create-unlinked procedure, validation and recovery boundaries |

The CSV follows [MS-GPAC message syntax](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/6494a0f2-8a16-40e2-b87d-328be7d732e0). It contains no per-user exclusions, global object SACLs or audit options. The precedence template follows the mechanism recommended in [MS-GPAC security considerations](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/e8edc8e2-4b91-433f-b1a2-672d4647e12f). Precedence is a prerequisite, not evidence of the winning domain policy or persistence.

| Shared profile mode | Export treatment |
| --- | --- |
| Exact 1, 2, 3 | Same exact mask; may turn off an opposite audit bit on a target |
| Minimum 1 or 2 | Blocked by default; explicit `PromoteToBoth` emits exact 3 and records each expansion |
| Minimum 3 | Exact 3, equivalent requirement |
| Minimum 0 | Omitted; no required bits |
| Optional | Omitted unless explicitly selected; selected positive mask is exact |
| Unchanged / Not Configured / Not applicable | Omitted; neither zero nor a delete instruction is emitted |
| Exact 0 / selected optional 0 | Blocked pending native validation of explicit-disable CSV semantics |
| Reference-only Windows defaults | Deployment export blocked |

A GPO CSV has no dynamic operation equivalent to WELA's local minimum-mask OR. Promoting a minimum to Both avoids dropping an unknown existing bit but can increase volume. No host snapshot is invented to resolve this. The normative [system-audit value specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/21ad2e80-3011-48ef-be13-cc11ff7bfeb1) distinguishes unchanged 0 from None 4, while Microsoft's [combined example](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/d77939fe-8fdc-4d06-b08a-13670cc8cbe7) also labels a 0 row No Auditing. This implementation rejects explicit-disable exports instead of choosing unverified behavior. Current non-reference built-in profiles use positive explicit masks; defaults remain documentary only.

## File safety and verification scope

The output's parent directory must exist and the final output directory must be new. Existing files/directories are never reused, and observed symlink/junction components are refused. Export writes an owned sibling staging directory, verifies all expected bytes against the installed profile, then publishes it with a directory rename that refuses a concurrent destination. Verification runs again at the final path. A failure can retain staging/output evidence for review; remove only the owned failed artifact after checking it. No Windows-policy recovery is needed because this workflow changes only package files.

Verify requires exactly the five expected regular files. It checks hashes, lengths and encodings and regenerates the expected policy/review from the installed shared profile schema. Changing a CSV and updating its manifest hash is insufficient: the intended settings and source provenance must still match the installed profile. A profile/generator/guide change can require regeneration and review; retain the WELA version used to create older packages. Hashes provide consistency checks, not a digital signature or trusted origin. Protect both WELA's source and the package and reverify immediately before review/use; concurrent filesystem changes after a check are not prevented.

`ExitCode=0` means the plan has no blockers or component verification succeeded, including a dry-run that produced no package. It does not mean a GPO was created, imported, linked or applied. Reports always retain `ImportableGpoBackup=false`, `DeploymentVerified=false` and `SigmaEvtxCredit=0`.

Only built-in advanced Security audit profiles and the precedence template are supported. Other registry controls, event-log sizing/retention/ACLs, SACLs, AD CS filters, WEF, PowerShell, firewall/SMB/provider settings, privileges and diagnostics are explicitly listed as unsupported. Sysmon is excluded. Follow [the deployment guide](gpo-package-deployment.md) for a genuine GPMC/LGPO preparation path and remaining domain acceptance work. Do not rename this folder or manufacture backup XML to make it look importable.

## Tests and remaining evidence

The offline suite covers shared source/role/build selection, every mode/mask translation, exact-zero/default refusal, optional/role omissions, source fingerprint drift, CSV/template contents, tampering even with updated hashes, fresh-directory collisions, dry-run, filesystem guards and public CLI option boundaries. The Windows workflow targets Server 2022/2025 under PowerShell 5.1 and 7, verifies cross-edition package compatibility, calls native `secedit /validate` on the generated template and checks unchanged effective audit masks/precedence. It does not apply audit CSV or create a domain GPO.

Accepted file syntax and package round-trips do not establish domain import, exact-disable behavior, GPO propagation or event generation. Genuine backup preparation, create-unlinked/import/readback, client/member/DC/AD CS lab application and benign event/collector evidence remain pending. Issue #2 therefore retains deployment acceptance work beyond this package feature.

The separate opt-in [`gpo-create`](gpo-creation.md) command can create a new disabled, unlinked candidate from a reviewed genuine narrow backup and matching package. Package export does not invoke it; positive AD/SYSVOL deployment acceptance remains separate.
