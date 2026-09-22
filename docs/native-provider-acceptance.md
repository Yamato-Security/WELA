# Native provider configuration acceptance

The dedicated `Native provider configuration acceptance` workflow tests the public `provider-packs` command on disposable GitHub-hosted Windows Server 2022 and 2025, separately under Windows PowerShell 5.1 and PowerShell 7. It complements the read-only manifest inventory and mocked failure tests described in [the provider-pack guide](native-provider-packs.md).

This fixture is destructive to the selected channels' temporary configuration and can discard records when restoring smaller buffers. It requires `-AllowDisposableProviderWrite`, `GITHUB_ACTIONS=true` and `RUNNER_ENVIRONMENT=github-hosted`; do not run it on ordinary machines. It makes no production configuration changes outside the existing public command's declared scope.

## Actual public behavior checked

- The real provider/channel registrations and expected event schemas must permit all four explicitly selected client-side packs: `dns-client`, `capi2`, `winrm` and `rdp-client`. Missing or incompatible metadata fails the fixture; it is never replaced with a mock or skipped success.
- Plan and Configure with `-DryRun` preserve prepared native settings. Unsupported preview and reader-grant options are refused before a recovery directory is created.
- Configure actually enables the four channels and applies their exact minimum buffers. A prepared 2 GiB WinRM buffer stays larger, and a prepared CAPI2 `Retain` mode stays intact. The complete descriptor is preserved; provider packs never request an Event Log Readers grant.
- Every Applied result and its original journal entry are compared with independent native before/after observations. Repeated Configure is idempotent and creates no write journal.
- Both manual DNS packs refuse configuration. The hosted image must genuinely lack the DNS Server service, and `dns-server-audit` must refuse that missing prerequisite. No DNS role is installed or removed to manufacture the result.
- A mixed CAPI2/manual-DNS invocation performs one real selected change and reports the other failure with a nonzero overall exit and exactly one journal entry. Partial application is explicit.

The fixture does not issue DNS queries, RDP connections or WinRM sessions, change service configuration, or intentionally generate test events. Ordinary background Windows events may occur while the channels are enabled. All rules retain zero Ready credit; enabling a source does not establish event fields, effective reader access, ingestion or matching backend queries.

## Preservation, cleanup and evidence

Before preparation, the fixture captures native settings and complete `wevtutil gl /f:xml` configuration for registered catalog channels and additional unselected Security, System, Application, AppLocker and DriverFrameworks controls. During public configuration it compares every selected XML field except the permitted enabled flag and maximum size; unselected registered channels must remain byte-for-byte equivalent at the XML level. It also compares the state/start type of EventLog, Winmgmt, WinRM, TermService and DNS, and all 59 effective audit masks.

Each selected channel has independent cleanup that restores original enablement, exact byte limit, descriptor and retention/backup mode. A failure restoring one channel does not skip the remaining channels. Final observations compare original full XML, service state and audit masks. Cleanup failure prevents a passing result. Owned child commands have bounded execution and output, and termination failures remain in the cleanup receipt.

`original.json`, public JSON reports, command output, actual journals, `completed.json`, `cleanup.json` and a SHA256 manifest are retained for seven days by the workflow. The manifest binds the fixture, product helpers, catalog, corpus and full reviewed rule-source bytes. Event records are not restored, and no retention-duration, Windows 11, domain/DC/ADCS, positive installed-DNS, forwarding or Sigma acceptance is implied. This advances issues #386 and #366 without closing their broader acceptance work.

The underlying enablement, size, retention and backup options follow Microsoft's [wevtutil command reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil). The product's existing channel floors and schema gates remain unchanged.
