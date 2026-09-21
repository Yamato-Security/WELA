# Reviewed collector firewall ingress

`wec-ingress` creates one new local Windows Firewall rule for a prepared Windows Event Collector. It addresses the collector ingress portion of #368. It is optional and separate from source configuration, subscription installation and `wec-update`.

The command supports elevated native 64-bit Windows Server 2022/2025 standalone or member servers. The Domain firewall must already be enabled, permit inbound/local rules, and have running BFE/MpsSvc services. WinRM and Wecsvc must be installed; the command does not start them. Domain membership and an active Domain network are not required for preparation, but an inactive Domain profile means the new rule does not currently allow traffic. Domain controllers and Windows clients are outside this command's initial support.

## Review and apply

Run in the same elevated operator logon on the collector, from the same WELA checkout. Replace the example local address with an address actually assigned to the collector and choose remote source scopes appropriate for your network:

```powershell
./WELA.ps1 wec-ingress -WecIngressName WELA-WEC-BranchSources `
  -WecIngressLocalAddress 10.20.30.40 -WecIngressRemoteAddress 10.20.40.0/24 `
  -WecIngressOutputPath C:\WelaEvidence\ingress-plan

# Inspect plan.json, including every address and the actual host/profile context.
# Supply the PlanHash printed by Plan after reviewing that exact file.
./WELA.ps1 wec-ingress -WecIngressAction Apply `
  -WecIngressPlanPath C:\WelaEvidence\ingress-plan\plan.json `
  -WecIngressPlanHash '<reviewed SHA256>' `
  -WecIngressOutputPath C:\WelaEvidence\ingress-apply
```

The parent evidence directory must exist; each output directory must be new on a local fixed drive. Output is protected for the operator, Administrators and SYSTEM. Plans are strict, size-bounded JSON and SHA256 binds their exact bytes. SHA256 is an integrity comparison, not a signature or independent authorization.

Select 1–8 exact local IPv4 addresses currently in Preferred state and 1–16 remote IPv4 literals or aligned `/24`–`/32` CIDRs. The initial implementation deliberately restricts scope size. It rejects wildcard/DNS/range/IPv6 addresses, host bits in networks, duplicate canonical addresses, loopback, unspecified and multicast/reserved destinations. Expand future address support with native validation rather than editing a generated plan.

The fixed rule is enabled, inbound Allow, Domain profile only, TCP local port 5985, remote port Any, with exactly the reviewed local/remote addresses. Edge traversal and block-rule override are disabled. The rule has no application, service, user or machine filter, so it also permits other HTTP/WinRM uses of port 5985 within that scope. `Authentication=NotRequired` and `Encryption=NotRequired` describe the new firewall rule's IPsec criteria; they do not modify WinRM authentication, transport or encryption settings.

The name must begin `WELA-WEC-`. It must be absent from both PersistentStore and ActiveStore, checked again immediately before native creation. The command never updates an existing rule. Windows duplicate-name rejection protects against a competing local creation. A Group Policy refresh or a later policy change can still supersede a local rule; configuration verification is a point-in-time observation, not a lock or persistence guarantee.

## Evidence and failure handling

Plan reads actual host/build/patch, MachineGuid, elevated operator SID/logon/groups, firewall profiles, assigned IPv4 addresses and service state, plus implementation hashes. Apply requires the same context, writes and flushes a Pending receipt before mutation, rechecks inputs, then uses `New-NetFirewallRule` once. It verifies PersistentStore and ActiveStore rule properties and all associated native filter classes. Native dotted netmasks are canonicalized for comparison. The existing `wec-collector` ingress prerequisite also compares explicit IP/network identities, so the same reviewed `/24` configuration recognizes Windows' dotted-netmask readback. Its existing broader IPv4/IPv6 CIDR support is preserved; this does not expand the narrower address selection of `wec-ingress`. Different networks, prefixes, IPv6 scope IDs, extra addresses, dynamic aliases and malformed masks remain mismatches or unreadable evidence. Raw native address strings remain in the reports.

`CreatedAndVerified` means the new rule's selected properties and filters matched during readback. `Refused` means no create attempt was made. `CreateAttemptedUnverified` means a rule may have been created: retain the Pending receipt and any after-state artifacts, inspect the named rule and correct or remove it explicitly. There is no automatic rollback or reuse of an existing rule, and replay of an applied plan is refused. Evidence filesystem failures are fatal and may leave only the already-flushed Pending receipt.

Other existing rules may allow broader access. This command does not claim that the collector's overall exposure is restricted to these addresses. It creates no WinRM listener, subscription, source GPO or service configuration and performs no network probe. Use the existing collector/source prerequisite and arrival checks separately. It grants zero Sigma readiness credit. Sysmon is excluded.

## Validation

Portable tests cover strict address/plan validation, source/context/hash drift, duplicate names, durable-before-write ordering, broader readback and partial failures. Public CLI guards reject unrelated options. The disposable Windows matrix uses Server 2022/2025 and PowerShell 5.1/7, an actual assigned local address and documentation remote subnet `192.0.2.0/24`; it exercises public Plan/Apply, native collision rejection, both policy stores and replay, checks that the real existing collector prerequisite accepts the reviewed `/24` and rejects `/25`, then removes only its uniquely named test rule and checks original rule properties, profiles and services. This is configuration evidence, not packet, listener or WEF delivery evidence.

References: [Microsoft New-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule?view=windowsserver2025-ps), [Get-NetFirewallRule and associated filters](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule?view=windowsserver2025-ps), [firewall security filters](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallsecurityfilter?view=windowsserver2025-ps).
