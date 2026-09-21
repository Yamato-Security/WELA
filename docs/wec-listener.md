# Reviewed local WEC HTTP listener

`wec-listener` plans and creates one new native WinRM listener for the WEC collector prerequisites. It supports an explicitly selected IPv4 address assigned to the actual local Server 2022/2025 standalone or member server. WinRM, WMI and the firewall services must already be running. Existing WinRM policy values require manual review and cause refusal. Domain controllers, remote hosts and listener updates are outside this command's scope.

```powershell
# Use an actual assigned local IPv4 address and a new private directory.
.\WELA.ps1 wec-listener -WecListenerComputerName $env:COMPUTERNAME `
  -WecListenerLocalAddress 192.0.2.10 -WecListenerOutputPath C:\WELA-Evidence\listener-plan

# Review plan.json, manifest.json and the retained configuration snapshots.
# Retain the SHA256 from that review before applying the same file.
.\WELA.ps1 wec-listener -WecListenerAction Apply `
  -WecListenerPlanPath C:\WELA-Evidence\listener-plan\plan.json `
  -WecListenerPlanHash '<reviewed SHA256>' -WecListenerOutputPath C:\WELA-Evidence\listener-apply
```

Plan writes review artifacts, including `plan.json` and `manifest.json` with `PlanHash`, and makes no Windows configuration change. Apply takes the computer and address from the reviewed plan. A separate new output directory retains its evidence. Mixed Plan/Apply inputs, unrelated options, `-Auto`, `-DryRun`, `-WhatIf` and unrecognized trailing arguments are rejected. Use Plan to review the proposed creation.

The fixed desired listener is `Address=IP:<selected IPv4>`, transport `HTTP`, port `5985`, URL prefix `wsman`, enabled, with blank hostname and certificate thumbprint. Wildcard listeners, any existing HTTP5985 listener and an existing selected Address/Transport pair prevent creation. WELA leaves those listeners in place for manual review. It does not narrow, replace, disable or remove an existing endpoint.

The plan binds the actual machine, operator/logon context, assigned address, implementation and original WinRM configuration/policy/listeners and firewall observations. Apply checks the reviewed hash and fresh context, writes pending evidence before its single creation attempt, then checks actual native configuration and `ListeningOn`. The fixed local creation worker uses the trusted native Windows PowerShell 5.1 engine under both Windows PowerShell 5.1 and PowerShell 7 hosts, with the fixed native 5.1 module directory and no execution-policy override. Its actual process, token and engine are retained as evidence. A host that cannot run this fixed adapter must resolve that prerequisite before applying.

| Result | Meaning |
| --- | --- |
| `ReviewRequired` | Plan artifacts are ready for review; no listener was created. |
| `CreatedAndVerified` | The new listener and expected native readback were observed, with the required preservation checks. |
| `Refused` | Preconditions, evidence or context failed before a creation attempt. |
| `CreateAttemptedUnverified` | The adapter started and creation was attempted or cannot be ruled out; the final state could not be completely verified. Review the pending/native evidence and current listeners before taking further action. |

No atomic Windows compare-and-set is available; another administrator or policy process can race observation and creation. There is no automatic rollback. An interrupted process can leave pending evidence and a created listener without a completed report. Use the retained original and current snapshots to identify what changed; this command never deletes a listener as a recovery shortcut.

Creating this listener exposes a standard WinRM endpoint on the selected address. It does not restrict the endpoint to event forwarding. Existing authentication and authorization still apply. WELA preserves authentication, services, existing listeners and firewall settings; it does not run `winrm quickconfig`, `Enable-PSRemoting`, alter TrustedHosts or grant remote users access. Use the separate [reviewed firewall ingress command](wec-ingress.md) where an approved firewall rule is needed.

This is one prerequisite for [collector deployment](wef-deployment.md). Listener readback does not prove remote reachability, client authentication, domain source membership, a subscription, collector arrival, sustained retention or Sigma readiness. Built-in Windows only; Sysmon is excluded. The disposable Windows tests exercise creation/collision/readback and fixture cleanup; connected domain-source acceptance remains separate.

Microsoft documents the native [WinRM listener selectors and configuration](https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management) and the [event-forwarding deployment prerequisites](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection).
