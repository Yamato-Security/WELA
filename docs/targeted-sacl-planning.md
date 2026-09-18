# Targeted SACL prerequisites in profile plans

`plan`, `audit` and `configure -Profile` now include a read-only `SaclPrerequisites` companion plan. It links File System, Registry and Handle Manipulation policy rows to WELA's existing `config/audit_sacl_targets.json` definitions. It lists each path, SID, audit flags, rights, inheritance, selected/effective policy masks and observation. The 50 WELA definitions are companion targets, **not claims that Microsoft, CIS or ASD requires every path**.

```powershell
# Offline: unknown host paths, hives, redirection and effective policy stay unknown.
./WELA.ps1 plan -Profile asd-native-2021-10 -Role Client -Build 26100 -IncludeOptional -PlanPath plan.json
# Local Windows: inspect paths and SACL readability before applying object policies.
./WELA.ps1 configure -Profile asd-native-2021-10 -IncludeOptional -DryRun -ResultsPath preview.json
# An explicit skip is retained as a telemetry gap in console and JSON results.
./WELA.ps1 configure -Profile wela-2.2.0 -SaclMode Skip -Auto -ResultsPath results.json
```

Explicit `-SaclMode` is accepted only with `-Profile` on plan/audit/audit-settings/configure; `configure-sacl -SaclMode Skip` is rejected before dispatch, because that separate command does not consume this plan.

No SACL is written by a profile command. Audit policy configuration retains its existing scope. `configure-sacl` remains a **separate, broader opt-in workflow**: it sets its own File System, Registry and Handle Manipulation policies and applies all existing WELA targets, including loading offline user hives. It does not consume this selected profile's plan. Review its scope before running it. This companion plan does not enable privileges, mount hives, install software or configure global object auditing.

On a matching local Windows role/build, the plan inventories ProfileList, Default and loaded HKU hives. Unloaded hives remain unresolved; it never silently substitutes the operator's user environment for another user's paths. Loaded-user Startup/AppData locations come from that user's unexpanded `User Shell Folders` values. Redirected, remote, missing, inaccessible and unresolved paths are explicit; UNC destinations are not contacted. Mapped network drives and reparse points in any path component are flagged before descendant or SACL inspection. These are point-in-time observations, not an atomic guard against concurrent path replacement. Enumeration failures, per-profile path errors and unmatched loaded hives make the inventory incomplete and remain visible as diagnostics. ProfileList paths expand only known machine variables; operator user variables are never substituted. An offline plan (or plan for a different role/build) inspects no host targets. `Skip` performs no user/target inspection.

Configured user-file paths beneath `AppData\Roaming` retain their complete relative suffix under the user's AppData known folder. The exact `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` root and its descendants use the separate Startup known folder, including its redirection; an unrelated directory named `Startup` does not. Unsupported roots, dot segments, unresolved variables and ambiguous path components remain unresolved before any known-folder read. This resolution adds no targets and does not enumerate other application folders.

`Exists` and `SaclReadState=Readable` mean only that the object and its SACL could be read. They do **not** prove the necessary audit ACE is present, inheritance reaches every descendant, mandatory/temporary profiles are covered, or a Security event was generated. All rows remain `GenerationReadiness=Conditional`, with zero usable-rule credit. A failure to read SACLs is reported separately from a missing path; elevated privileges may be necessary for those reads.

## Source-specific distinctions

[Microsoft WEF Appendix B](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection#appendix-b---recommended-minimum-registry-system-acl-policy) shows HKLM Run/RunOnce audit entries for **Authenticated Users**, Success, this key and subkeys. Run specifies SetValue/CreateSubKey; RunOnce adds Delete. A Microsoft WEF profile includes these exact audit-entry rows separately from WELA's Everyone, Success+Failure targets. The screenshots' DACL/owner settings are not proposed for copying. Appendix A leaves Registry Not Configured; the planner exposes that unresolved policy prerequisite rather than silently enabling it.

[ASD native guidance](https://www.cyber.gov.au/business-government/detecting-responding-to-threats/event-logging/windows-event-logging-and-forwarding) makes File System and Registry success/failure auditing optional. `-IncludeOptional` selects those existing profile controls; otherwise the targets retain an explicit policy gap. Sysmon is outside this feature's scope.

## Isolated Windows validation still required

On a snapshot, save the plan and effective policy, apply an explicitly approved targeted SACL, perform a benign operation on a disposable registry key/file that inherits the selected rule, and match Security event XML (for example 4657/4663) to that object, subject and access mask. Check relevant 4656/4658 events separately if Handle Manipulation is needed. Verify forwarding at the collector where required. Repeat for loaded/unloaded users, redirected paths and relevant client/server roles. Preserve before/after ACLs and remove only disposable test objects. This PR's mocked tests and native read-only CI do not supply event-generation or forwarding evidence, so issue #373 remains open for that acceptance work.
