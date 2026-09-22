# Explicit LDAP 1644 diagnostics

Normal `configure` preserves existing LDAP diagnostics and explains that 1644 is not selected. It no longer sets `15 Field Engineering=5` automatically on domain controllers. Microsoft's [current MDI guidance](https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection#update-legacy-configurations) no longer requires these diagnostic settings. Security auditing and the other MDI prerequisites remain separate.

The dedicated local workflow supports Server 2022/2025 DC builds 20348/26100 in 64-bit Windows PowerShell 5.1 or PowerShell 7. Client, member server and member-server CA hosts are not applicable. Unknown or conflicting role/build evidence blocks writes; no NTDS settings are created on a non-DC.

LDAP options require the dedicated `ldap-diagnostics` command. Supplying them to another command, including `configure -Profile`, stops before that command runs.

```powershell
./WELA.ps1 ldap-diagnostics -LdapAction Audit -ResultsPath ldap-before.json
./WELA.ps1 ldap-diagnostics -LdapAction Plan -LdapMode Diagnostic -LdapSearchTimeMs 100
./WELA.ps1 ldap-diagnostics -LdapAction Configure -LdapMode Diagnostic -LdapSearchTimeMs 100 -DryRun
./WELA.ps1 ldap-diagnostics -LdapAction Configure -LdapMode Diagnostic -LdapSearchTimeMs 100 -Auto -BackupPath C:\WelaRecovery\ldap-01 -ResultsPath ldap-result.json
```

`Preserve` is the default mode, including when Configure is selected. It changes no settings. `Diagnostic` explicitly requests Field Engineering level 5 and only the thresholds supplied by the operator. Omitted thresholds retain their existing typed values; they are not silently lowered to 1. Thresholds must be positive integers through 2147483647. Windows treats an absent/zero time threshold as its documented default; use cleanup to remove an override instead of supplying zero.

| Option | NTDS Parameters value | Unit | Microsoft documented default, not a host observation |
|---|---|---|---:|
| `-LdapSearchTimeMs` | Search Time Threshold (msecs) | milliseconds | 30000 |
| `-LdapExpensiveThreshold` | Expensive Search Results Threshold | entry threshold | 10000 |
| `-LdapInefficientThreshold` | Inefficient Search Results Threshold | entry threshold | 1000 |

These values are described in Microsoft's [1644 diagnostics procedure](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/event1644reader-analyze-ldap-query-performance). The example's 100 ms is a starting point to evaluate, not a baseline requirement. Level 5 also generates other Directory Service events. Measure event rate, log rollover and DC workload over a bounded interval before wider rollout. WELA neither issues LDAP searches nor measures that volume automatically.

`MdiCleanup` is an explicit removal choice. It removes **all four named values** shown in the plan, including customized values: Field Engineering first, followed by the three thresholds. It leaves their registry keys and unrelated diagnostic values intact. Select it only after reviewing existing operator diagnostics; normal configure and Preserve never perform cleanup.

```powershell
./WELA.ps1 ldap-diagnostics -LdapAction Plan -LdapMode MdiCleanup
./WELA.ps1 ldap-diagnostics -LdapAction Configure -LdapMode MdiCleanup -DryRun
```

Writes require a fresh complete snapshot and a saved `before.jsonl` recovery record containing original existence, type and value for every control. Unknown types and concurrent changes block writes. Each selected threshold is read back before verbose logging is enabled; errors stop the remaining changes and produce a nonzero result. Repeated configuration is idempotent, and the final check detects drift in selected and preserved values. Dry-run does not create a backup directory or modify Windows. A partial failure retains its journal; it does not trigger automatic restoration over newer changes.

For recovery, compare fresh values with both the journal's original state and this run's desired values. Restore original values/types only where this run's changes still remain; remove only a value that was originally absent. Preserve any newer operator changes and keep the recovery journal. MDI cleanup is not a general rollback command.

Tests cover default preservation, explicit setup/cleanup, positive bounds, type/read/write errors, journal ordering, stale plans, races, partial failures, repeated application and final drift. Windows CI queries native role applicability without configuring a DC. Before closing #383, use an isolated DC snapshot to verify a benign query against the selected thresholds, retain matching 1644 XML and before/after policy, measure volume, and verify forwarding. Registry readback is not event-generation or Sigma detection evidence. Sysmon is out of scope.
# Issue 383 coverage

LDAP 1644 diagnostics are opt-in and role-scoped. `Preserve` changes nothing, `Diagnostic` accepts explicit threshold values, and `MdiCleanup` removes only the four named legacy NTDS values after a fresh local-DC observation. WELA never silently overwrites existing diagnostics, and event volume, forwarding, and MDI compliance remain separate validation steps.
