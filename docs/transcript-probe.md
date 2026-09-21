# Automatic Windows PowerShell transcription probe

`transcript-probe` checks whether one fixed Windows PowerShell 5.1 child, launched as the current WELA account, produces its own completed **automatic** transcript in an already configured local destination. It does not change policy, ACLs, services or shares. It never calls `Start-Transcript` as a fallback. Transcripts are not EVTX, and the report always grants zero Sigma/EVTX credit.

This is the current-account local-writer acceptance portion of #376. The existing [transcription audit/configure command](powershell-transcription.md) remains separate. UNC/share acceptance, remote collection, retention and testing other writer accounts remain separate work.

## Commands

Run from native 64-bit Windows PowerShell 5.1 or PowerShell 7 on a supported Windows 11, Server 2022 or Server 2025 host. The child being tested is always native Windows PowerShell 5.1; running WELA in PowerShell 7 does not test PowerShell 7 transcription.

```powershell
# Default Plan: inspect the selected destination and prerequisites.
.\WELA.ps1 transcript-probe -TranscriptProbeDirectory C:\Transcripts

# Explicit Run: one fixed child, then verify its completed automatic transcript.
.\WELA.ps1 transcript-probe -TranscriptProbeAction Run `
  -TranscriptProbeDirectory C:\Transcripts `
  -TranscriptProbeOutputPath C:\Evidence\transcript-unique-run
```

The output directory must be new, have an existing parent, and be outside the transcript destination. WELA creates it with access for the current account, SYSTEM and Administrators. `Plan` launches no probe child and creates no explicit evidence directory. An already enabled transcription policy can naturally transcribe the WELA invocation itself, including a Plan invocation.

An enabled machine `EnableTranscripting` DWORD policy and an explicit literal `OutputDirectory` string must already exist and match the selected local fixed-drive directory. Both shared registry views must agree. Current-user policy and invocation-header settings are also recorded and checked for known types. This initial command does not infer default destinations or accept a current-user-only policy. Winmgmt must already be running for read-only host observations.

The account needs directory/date-folder metadata and listing access, plus read access to the new transcript. A write-only drop-box destination may accept automatic transcripts but cannot be proven by this verifier. Permission failures remain unverified; WELA does not broaden access to obtain proof.

## What a successful result means

`Status: CompletedAutomaticTranscript` and `WriterAuthorization: ObservedForThisChild` mean the local verifier observed exactly one fresh matching completed transcript from the fixed child during this run. The evidence binds the following:

- The actual child PID, executable, PowerShell 5.1 Desktop version, command arguments and loaded engine assembly hash.
- Actual current-account SID, logon authentication ID and group attributes in the parent and child. Full before/after token observations are retained within each process; cross-process matching uses the authorization identity and groups because process startup can change privilege flags.
- Unique standalone begin/end output lines, the native engine's localized header/footer resource templates, header identity/PID/host command, and header/footer timestamps within the observed launch/exit window.
- Existing policy, executable/source hashes, host and time-zone observations, plus handle-based destination/date-folder identity and owner/group/DACL observations before and after the operation.
- Bounded raw matching transcript bytes, SHA-256 hashes and a matching file handle retained through final checks. Reparse points, multi-link files and identity/descriptor drift are refused.

The fixed child uses `-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File` with WELA's bundled worker and a generated nonce. The execution-policy option is local to that process; it does not change stored policy or override enforced Group Policy. No arbitrary command, credential or alternative executable can be supplied to this command.

Output preparation and initial observations precede the parent token interval. The measured interval covers the worker and transcript verification; the report retains both parent token snapshots. The child records its own before/after interval. Token differences, ambiguous transcripts, incomplete output, unexpected formats or context drift fail verification. A completed transcript proves this observed operation, not continuing authorization, other users' access, remote share acceptance, reliable collection or application of every baseline recommendation.

This is local consistency evidence, not tamper-proof attestation against another process controlled by the same account or an administrator. The fixed nonce, PID, command and time checks provide correlation; they do not establish exclusive writer attribution against a malicious local actor.

## Bounds and artifacts

The inventory covers only the previous, current and next local calendar-date folders, with at most 256 entries in total. Existing transcript contents are never read. The verifier considers at most 32 new file identities, reads at most 1 MiB per candidate and 4 MiB in total, and accepts exactly one matching transcript. Unexpected directories, names, encodings or candidate times remain unverified. Busy destinations can exceed these conservative bounds.

The worker has a 30-second deadline. Each redirected output stream retains at most 64 KiB, with bounded pipe-drain and termination waits. The report includes explicit diagnostics for refusal and incomplete evidence; no fallback obtains a positive result.

A completed Run writes `result.json`, `worker.json` and the exact matching `transcript.txt` bytes into the protected output. Failed runs that reached output preparation keep diagnostic artifacts and exit nonzero. Prerequisite failures can occur before an output directory exists. Source transcripts are retained in their configured destination; WELA never removes them.

## Validation

Portable fixtures exercise the actual native-format matcher, identity/time/nonce/version refusals, localization templates, encoding limits, policy types, drift and dedicated CLI guards. The opt-in hosted Windows fixture provisions only its own standard account and destination, enables a temporary machine transcription policy, and invokes the public command in fresh processes. It tests an allowed writer and then a denied writer, preserves both original typed policy views, restores the original destination ACL and removes only the owned account. This fixture is gated to disposable standalone GitHub-hosted Server 2022/2025 machines and both WELA host engines. It never substitutes an explicit transcript for automatic policy output.

Microsoft documents automatic policy transcription and machine-policy precedence in [Turn on PowerShell Transcription](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings?view=powershell-5.1#turn-on-powershell-transcription). The verifier reads the actual installed engine's transcript resource templates rather than assuming an English header.
