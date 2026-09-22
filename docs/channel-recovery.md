# Reviewed native channel recovery

`channel-recovery` restores **one completed `channel-settings` operation** on one exact channel from the bundled Microsoft WEF Appendix C profile. It can restore the original enabled state and size, and remove only the exact Event Log Readers read ACE that operation added. It does not restore other configuration commands, partially completed original writes, event records, subscriptions or arbitrary channels. Sysmon is excluded.

```powershell
./WELA.ps1 channel-recovery -ChannelRecoveryJournalPath C:\WELA\original\before.jsonl `
  -ChannelRecoveryOriginalResultsPath C:\WELA\original-results.json `
  -ChannelRecoveryChannel 'Microsoft-Windows-CAPI2/Operational' `
  -ChannelRecoveryOutputPath C:\WELA\recovery-plan

# Inspect plan.json and manifest.json; independently retain manifest PlanHash.
./WELA.ps1 channel-recovery -ChannelRecoveryAction Restore `
  -ChannelRecoveryPlanPath C:\WELA\recovery-plan\plan.json `
  -ChannelRecoveryPlanHash REVIEWED_SHA256 `
  -ChannelRecoveryOutputPath C:\WELA\recovery-run `
  -ChannelRecoveryAllowShrink -ChannelRecoveryAllowDisable -ChannelRecoveryAllowRevoke
```

Supply only the consent switches the reviewed plan requires. **Shrinking can discard records; disabling stops channel generation; removing a read grant can interrupt collection.** These are separate decisions. Plan is read-only apart from new protected evidence files. Restore accepts a reviewed plan/hash and a new output directory; `-Auto`, `-DryRun`, `-WhatIf` and unrelated command options are rejected. There is no automatic rollback or continuation after a partial failure.

The original journal must contain exactly one matching entry, with the same typed `Before`, `Desired` and target as one `Applied` result. The command independently rebuilds the enable/minimum-size/read-grant transformation from the current bundled profile. Unknown schemas, Boolean values in text/size fields, duplicate JSON properties, mismatched journals, unexplained post-write changes, missing read-grant authorization and unchanged operations are refused. The selected operation may be recovered even when another channel failed during the original invocation; it must itself be completed and fully consistent.

Current settings must exactly match the original confirmed after-state. For descriptors, equality means the complete binary descriptor, including owner, group, SACL, DACL, resource-manager control and all ACE bytes/order. The canonical read-grant planner must reproduce the exact original addition, and SDDL conversion must round-trip without loss. An unrelated new ACE or another changed setting requires manual review; recovery never removes it. A previous read grant that was already present is preserved.

Only originally changed fields are written, in size, descriptor, then enablement order. Each write has a flushed pending receipt, a fresh complete settings/metadata check and actual primary-token check, native `wevtutil` exit validation, independent readback, and a confirmed receipt. Other channel properties, including retention, path, provider parameters and isolation, must remain unchanged. A final read checks the full target. Recovery changes no other channel, audit policy, group membership, service or forwarding configuration.

| Result | Meaning |
| --- | --- |
| `ReviewRequired` | A new plan and hash were retained; no native write occurred. |
| `Refused` | Evidence, consent or current context did not authorize a write. |
| `RestoredAndVerified` | Every selected original field was restored and observed with preservation checks. |
| `RestoreAttemptedUnverified` | At least one native write was attempted; inspect pending, observed, confirmed and failure-state receipts before manual action. |

`ConfirmedFields` identifies steps whose immediate readback succeeded; a later failure does not establish that those settings stayed unchanged. Loss of power, process termination or output-storage failure can leave pending evidence without a final manifest. A read-grant removal could succeed even if the caller subsequently cannot read metadata; that remains unverified, without rollback. There is no atomic Windows compare-and-set, so another administrator can race the final check.

Inputs and outputs must use ordinary local paths supported by WELA's protected recovery artifact helpers. Current host identity, actual operator/logon, source files and native executable/reader assembly hashes are bound to the plan. Plan and Restore must use the same installed implementation and PowerShell version. **Old version-1 journals contain only historical ComputerName; current guards do not authenticate historical ownership.** Treat original evidence as trusted operator records. Updating WELA invalidates older review plans; create and review a new plan rather than editing its fingerprints.

Windows validation uses explicit disposable GitHub-hosted Server 2022/2025 fixtures under Windows PowerShell 5.1 and PowerShell 7. The fixture calls public Configure then Plan/Restore for actual CAPI2 enable/size changes, with and without the optional read ACE. It tests each missing consent, actual later size drift, replay, unsupported preview options, other-channel preservation, retained hashes, and exact original fixture configuration/all audit masks at cleanup. Shrinking during fixture cleanup can discard intervening records. Windows 11, domain/DC/CA forwarding identities, event generation, persistence through policy refresh, retention duration and backend Sigma evaluation remain separate acceptance work. No rule-readiness credit is granted.

See [native channel configuration](native-channel-access.md) for original journal creation and [actual channel reads](channel-read.md) for separate current-token query evidence. [Microsoft's `wevtutil` contract](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil) documents channel enablement, maximum size and channel access; buffer configuration is not a retention guarantee.
