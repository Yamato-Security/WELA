# Conditional IPsec Main Mode auditing

The built-in `microsoft-stronger-reviewed-2026-09` profile enables IPsec Main Mode Success and Failure only when the operator selects `-IncludeOptional` **and** WELA observes a positive native prerequisite on the local Windows host. Other profiles and operator-owned custom profile requirements keep their existing meanings.

```powershell
# Observe the actual local host and retain the evidence in the shared plan.
./WELA.ps1 plan -Profile microsoft-stronger-reviewed-2026-09 -IncludeOptional -PlanPath ipsec-plan.json

# Review the complete stronger profile before configuring it: this profile also selects other audit subcategories.
./WELA.ps1 configure -Profile microsoft-stronger-reviewed-2026-09 -IncludeOptional -DryRun -ResultsPath preview.json
./WELA.ps1 configure -Profile microsoft-stronger-reviewed-2026-09 -IncludeOptional -Auto -BackupPath new-backup -ResultsPath result.json
```

WELA uses the built-in NetSecurity module to read `Get-NetIPsecRule -PolicyStore ActiveStore` and `Get-NetIPsecMainModeSA`. It makes no connection-security, firewall, authentication, service or network changes. The existing configuration engine changes only the selected audit requirements and their advanced-audit precedence prerequisite.

| Observation | Meaning and conditional configuration behavior |
| --- | --- |
| `Applicable` | Both inventories completed with recognized records, and either an enabled, healthy, non-exemption ActiveStore rule or a current main-mode SA was observed. With explicit optional selection, the audit setting can be assessed/applied. |
| `NotObservedWithinScope` | Both inventories completed, with no qualifying rule or SA. Preserve the audit setting and report `Skipped`, including when the existing mask already equals S+F. This is **not** a claim that all IPsec is unused. |
| `Unknown` | Offline scenario, failed/partial/malformed/duplicate/capped inventory, or an enabled securing rule with uncertain health. A selected configuration control fails without writing that audit setting. Independent profile controls retain their normal behavior. |

Disabled rules and rules with both `InboundSecurity` and `OutboundSecurity` set to `None` do not establish the prerequisite. Rule names, enabled/security/health values, qualification, association names/endpoints, timestamps, host and separate source outcomes remain in `conditionalPrerequisite` in the plan. Each source is limited to 4096 records; exceeding the limit is Unknown. The inventory is sequential and point-in-time, not an atomic system snapshot. Native calls have the operating system's normal completion behavior; this feature does not impose a wall-clock query timeout.

An enabled healthy rule in the effective store establishes **configured policy**, not that its address/profile/interface filters currently match traffic, that authentication succeeds, or that any event is emitted. WELA does not inspect the associated filters as an enforcement proof. Absence does not exclude legacy policy, VPN use, other IPsec providers or an idle deployment. Investigate those separately; use a reviewed custom profile if your intended exact audit requirement is independently established outside this automatic scope.

Offline plans retain Unknown and never query the machine running the planner. Live public `plan`, `audit-settings -Profile` and `configure -Profile` collect only for this built-in stronger-profile condition. A role/build scenario for a different host remains offline. The optional flag is still necessary when positive evidence exists; no extra setting is selected automatically. Offline GPO/Intune exports retain their existing operator-selected deployment semantics and do not claim that endpoint prerequisites have been observed.

The public configuration runner retains fresh native observations in the control's `PrerequisiteObservations`. It checks before assessment, after the operator prompt and recovery journal immediately before the native policy write, after application and during final verification. Losing the prerequisite after planning or confirmation prevents that write; losing it after a completed write produces a failed verification with the recorded evidence and recovery journal. The direct shared profile executor also checks its selected condition initially and immediately before mutation. No lock prevents concurrent changes after the final check, and no automatic policy rollback is performed. Existing audit recovery procedures still apply.

The read-only inventory itself requires access to the local native providers; configuration requires elevation. Records can contain policy identifiers and peer IP addresses, so retain exported reports with your other administrator evidence.

## Validation boundaries

Portable tests exercise disabled/exempt rules, malformed/failed/capped observations, offline planning, explicit optional selection, source-profile isolation, both configuration paths and prerequisite loss after a prompt. The gated native fixture uses fresh rules between documentation-only IP addresses, exercises the public plan/dry-run/configure commands, and removes its owned rule after confirmation to test native pre-write refusal. It restores all 59 original audit masks, the typed precedence value or its absence, and the original rule inventory. The fixture generates no network traffic or main-mode negotiation.

Native CI covers Server 2022/2025 under Windows PowerShell 5.1 and PowerShell 7. Actual SA-positive collection, Windows 11, domain-managed/legacy/VPN scenarios, successful and failed negotiation XML, event volume, collection and detection acceptance remain separate. This advances the prerequisite-detection part of issue #370; it does not close that issue or establish any Sigma eligibility. Sysmon is excluded.

Sources: Microsoft's [stronger audit recommendations](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations), [effective IPsec rule inventory and security semantics](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netipsecrule?view=windowsserver2025-ps), [current main-mode associations](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netipsecmainmodesa?view=windowsserver2025-ps), and [native rule/filter creation semantics](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netipsecrule?view=windowsserver2025-ps).
