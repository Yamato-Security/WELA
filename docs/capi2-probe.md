# Fixed local CAPI2 certificate-chain probe

`capi2-probe` measures one built-in source on Windows Server 2022/2025: an offline native chain build for a newly generated ephemeral self-signed certificate, followed by one matching CAPI2 Operational event 11. The expected chain outcome is an untrusted root. Success means that this local operation and event were observed; it does not mean that the certificate is trusted.

```powershell
./WELA.ps1 capi2-probe -Capi2ProbeAction Plan
./WELA.ps1 capi2-probe -Capi2ProbeAction Run -Capi2ProbeOutputPath C:\Evidence\new-capi2-probe
```

Plan reads prerequisites and creates no files. Run requires a new directory on a local fixed drive; its evidence directory blocks inherited broad access. Use an existing token that can read `Microsoft-Windows-CAPI2/Operational`. The channel must already be enabled. The probe does not change channel configuration, audit policy, services, certificate stores, trust settings or reader permissions. Existing native-channel configuration commands remain separate.

Run launches the same PowerShell executable in a fresh worker with a parent-generated nonce and a twenty-second process deadline. The worker creates an unnamed ephemeral Microsoft Software Key Storage Provider RSA-2048 key, signs an in-memory certificate with `CN=WelaCapi2Probe_<nonce>` and a ten-minute validity interval, then calls `CertGetCertificateChain` once. The certificate has no AIA, CRL or other extensions. The key is disposed and never exported; the retained PEM/DER contains only the public certificate.

The fixed native flags are `0x80002104`: `CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL`, `CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY`, `CERT_CHAIN_DISABLE_AIA` and `CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE`. No revocation-check request, additional store, custom trust engine or end-certificate caching is selected. These per-call flags prevent network retrieval by the chain operation; no machine-wide network or trust policy is altered.

Evidence must agree on the actual worker PID, caller SID/logon/group context, before/after token observations, generated DER/subject/thumbprint/SHA-256 and nonce. A native precise UTC interval surrounds the chain call; the event must fall within those exact inclusive bounds and after the observed channel record boundary. The matcher requires provider GUID, channel, event11 version0, native task/opcode/keywords, source computer, security SID, certificate references, offline flags, one certificate element and the expected untrusted-root result. Incomplete, ambiguous, capped or changed-context evidence remains `Unverified` and exits nonzero.

Collection waits up to 15 seconds by default (`-Capi2ProbeTimeoutSeconds 1..30`), queries at most 64 candidates and requires exactly one match. The bundle retains before/after context, worker operation including public certificate DER, public certificate PEM, raw matched event XML and artifact hashes. Failed matching retains up to four bounded candidate XML records. These local hashes detect altered artifacts; they are not a remote attestation or signed chain of custody.

This probe grants no ready-rule credit. It does not exercise TLS, remote connections, revocation retrieval, certificate enrollment, WEF delivery, the existing CAPI2 pack's event70 mapping, a Sigma rule or backend translation. Issues #386 and #367 have broader remaining acceptance criteria. Sysmon and external telemetry are excluded.

## Validation

`tests/Capi2Probe.Tests.ps1` validates certificate binding, native-result constraints, prerequisite guards, exact XML source/field checks and UTC boundaries with portable fixtures. `tests/Capi2Probe.Cli.Tests.ps1` checks public option isolation. Synthetic fixtures do not prove Windows telemetry.

`tests/Capi2Probe.Windows.Tests.ps1 -AllowDisposableChannelWrite` is restricted to opted-in disposable GitHub-hosted standalone Server 2022/2025. It invokes three independent public probes under Windows PowerShell 5.1 and PowerShell 7. Only the fixture may temporarily enable CAPI2; it retains the original and restored channel configuration, checks CurrentUser/LocalMachine My, Root and CA inventories, preserves all probe bundles and writes cleanup evidence even on failure. Native results must be assessed from the current workflow artifacts.

## Microsoft API references

- [CertGetCertificateChain flags and ownership](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetcertificatechain)
- [CERT_CHAIN_PARA](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_chain_para), [CERT_CHAIN_CONTEXT](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_chain_context), [CERT_SIMPLE_CHAIN](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_simple_chain) and [CERT_TRUST_STATUS](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_trust_status)
- [Unnamed CngKey creation is ephemeral](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.cngkey.create)
- [CertificateRequest.CreateSelfSigned](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.certificaterequest.createselfsigned)
- [GetSystemTimePreciseAsFileTime](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimepreciseasfiletime)
