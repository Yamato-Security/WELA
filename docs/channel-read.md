# Actual current-token channel reads

`channel-read` queries selected built-in local logs under the primary token that actually runs WELA. It records the query result separately from the channel settings shown by `channel-settings`. Launch WELA through your established account/service procedure under the identity you want to test; this command accepts no credentials or impersonation options.

```powershell
.\WELA.ps1 channel-read -ChannelReadName Security,Microsoft-Windows-CAPI2/Operational -ChannelReadOutputPath C:\WELA-Evidence\reader-001
```

Use an existing local fixed-drive parent writable by that account and a **new** output directory outside the WELA source tree. The result is `result.json`, with inheritance disabled and access for the current user, SYSTEM and Administrators. Existing output, reparse paths, remote/device paths and alternate streams are rejected. These checks are not an atomic defense against a concurrent administrator replacing filesystem objects. Treat the result as sensitive operational evidence.

One to eight exact channel names from `config/native_channel_profile.json` are accepted. The inventory contains Security, System, Application, Windows PowerShell, CAPI2 and other built-in WEF channels. Sysmon, ForwardedEvents, arbitrary files, remote sessions and caller-supplied XPath are excluded. Supported host context is Windows 11 builds 22000/22621/22631/26100/26200 and Server 2022/2025 builds 20348/26100, including observed member/DC roles. Role support does not mean those roles have all been acceptance-tested.

The native [`EventLogReader`](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogreader.readevent?view=netframework-4.8.1) uses a local `LogName` query, XPath `*`, reverse direction, a batch of one and a five-second read timeout. Query setup and separate metadata calls do not have an overall five-second deadline. It verifies the single query status and, when an event is returned, checks its channel and records only bounded System metadata: record ID, provider, ID/version, computer and creation time. No rendered messages, event payloads or raw XML are exported, and no logs are cleared. The report is capped at one MiB.

| Query status | What it establishes |
|---|---|
| `EventObserved` | This token read one event from this channel at the recorded query time. |
| `ReadAllowedEmpty` | The native query completed successfully with no record returned. Access was allowed; event generation is unproven. |
| `Denied` | Windows rejected the actual query with access denied. |
| `Absent` | Windows reported a missing local channel/path. |
| `Unknown` | A timeout, other native error, incomplete status or invalid event provenance prevented a conclusion. |

Native error codes are retained when the runtime exposes them; .NET Framework may provide only a typed exception and diagnostic. Localized message text is not parsed to infer status.

A completed observation returns exit 0 only when every selected channel is `EventObserved` or `ReadAllowedEmpty`. Denied, absent and unknown queries return 1 while retaining the report. A changed reader, host or source fingerprint produces `Unverified`, exit 1, and clears every `AccessVerified` conclusion. Raw query observations remain available for diagnosis. Output/setup failures also return nonzero and may leave a partial directory without a result.

Channel metadata is an independent observation: inability to read configuration or SDDL does not invalidate a successful actual event query. Conversely, a readable descriptor or Event Log Readers ACE is never substituted for a query. The report captures the actual user, group SID inventory, administrator membership, process, token ID, logon authentication LUID and [`TOKEN_STATISTICS.ModifiedId`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_statistics). It checks these before/after queries, rejecting token changes and impersonation. Loaded native helper types must match the exact source bytes compiled in the current process; source changes require a fresh PowerShell session. Group SID inventory is not an access calculation or a group-attribute/privilege dump. The event-query adapter does not enable privileges or change groups, channel ACLs, policy, subscriptions or services. Output-directory ACL and metadata preparation occurs before the query-token interval because Windows/.NET may temporarily adjust available privileges while preparing evidence storage or inspecting configuration.

Evidence applies only to the observed local process token and time. It does not prove a different service token can read, that a producer generates the desired events, that a WEF subscription delivers them, or that a backend executes Sigma rules. `ReadyRuleCredit` remains zero. An administrator's success is not evidence for the intended forwarding identity. Run under that identity and retain corresponding source/collector evidence separately.

## Validation and remaining acceptance

Safe fixtures cover status/exit semantics, independent metadata denial, token/host/source drift, overwritten outputs, channel scope and CLI refusal. A separate gated GitHub-hosted Server 2022/2025 × Windows PowerShell 5.1/PowerShell 7 fixture creates one owned standard account, temporarily adds a CAPI2 read-deny ACE, and observes an actual denial in a fresh logon. It replaces only that fixture ACE with a read-only allow and checks another fresh standard-user query, plus one actual administrator Application event. It verifies complete original channel settings restoration and deletes only the SID-matched owned account. The product has no fixture override. The fixture does not clear or enable CAPI2, and the allowed query may legitimately be empty. Failure stops the acceptance claim and preserves cleanup evidence; owned filesystem evidence is retained for the ephemeral runner lifecycle.

Windows 11, member-domain/DC/ADCS, intended forwarding service-token, policy-refresh and multi-host arrival acceptance remain separate. This advances issue #367 without closing its full WEF acceptance requirements.
