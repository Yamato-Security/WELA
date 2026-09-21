# Resume a pending AD CS auditing restart

`adcs-resume` provides a deliberate recovery path after a dedicated `adcs-auditing Configure` wrote `AuditFilter=127` but recorded `RestartPending`. It supports the same dedicated Server 2022/2025 CA scope as [AD CS auditing](adcs-auditing.md). It does not write registry values, change auditing, start a stopped CA, change dependent services or submit certificate requests. Sysmon is excluded.

Microsoft requires [restarting Certificate Services after changing its audit filter](https://learn.microsoft.com/en-us/defender-for-identity/deploy/event-collection-overview). Finding 127 on a later audit cannot establish activation. The existing Configure command still leaves an unchanged filter alone; recovery requires its own reviewed plan and explicit restart consent.

## Review, dry run, resume

Use an elevated, non-impersonated native 64-bit PowerShell 5.1 or 7 session on the original CA in an appropriate maintenance window. Retain the original dedicated command's `before.jsonl` and failed results JSON. All paths must be on local fixed drives with existing protected parents; the plan and receipt directories must be new. Avoid concurrent CA, policy and evidence-file administration.

```powershell
.\WELA.ps1 adcs-resume -AdcsResumeJournalPath C:\Evidence\ca-journal\before.jsonl -AdcsResumeResultsPath C:\Evidence\ca-result.json -AdcsResumeOutputPath C:\Evidence\restart-plan

# Review restart-plan\plan.json and its complete expected CA/operator context.
$plan = 'C:\Evidence\restart-plan\plan.json'
$hash = (Get-FileHash -LiteralPath $plan -Algorithm SHA256).Hash.ToLowerInvariant()
.\WELA.ps1 adcs-resume -AdcsResumeAction Resume -AdcsResumePlanPath $plan -AdcsResumePlanHash $hash -DryRun

# During the approved maintenance window, from the same operator context:
.\WELA.ps1 adcs-resume -AdcsResumeAction Resume -AdcsResumePlanPath $plan -AdcsResumePlanHash $hash -AdcsResumeAllowRestart -AdcsResumeOutputPath C:\Evidence\restart-receipts
```

Plan reads original evidence and current state, then creates a private `plan.json`. DryRun revalidates everything and writes no files or service changes. Resume requires the exact reviewed plan hash and `-AdcsResumeAllowRestart`; generic `-Auto` and `-AllowRestart` are refused. It independently rebuilds the plan, writes and flushes `reviewed-plan.json` and `pending.json`, rechecks the original evidence, implementation, actual operator and CA, and then calls the existing non-force Certificate Services restart. The pending receipt records intent, not completed work.

## Eligibility and refusal

The original dedicated result must be a failed, non-dry-run Configure with `RestartPending`, matching settings and one failed filter result that agrees with its journal. The earlier filter must have been a known DWORD below 127 or absent. The current installed source profile must match the original report. Legacy configure output or a plain audit showing 127 is insufficient.

The current CA must still be running in the exact service instance recorded after that write, with unchanged host/build/role, Active CA, certificate identities, typed filter, effective Certification Services auditing, audit precedence, service start mode and dependent-service states. Running dependents are refused. Plan binds the current machine GUID, operator SID, group SID list and elevation/impersonation context. Group SIDs are context observations, not an access simulation; Windows enforces service access. Repeat observations and pre/post checks refuse detected drift.

A newer process, reboot, stopped service, changed CA/certificate, replaced input, changed implementation/profile, different operator or altered policy requires separate operator investigation. This command does not generalize old evidence to another CA, recreate a lost service, restore earlier values or automatically retry a failed resumed restart. A successful resume makes the original plan ineligible because its recorded process is no longer current.

## Results and limitations

`RestartObserved` means the service has a newer start time within the attempt window, is Running, and all other observed CA/settings/service properties remain equal in readback and final verification. It does not prove request-event generation, forwarding, enterprise template behavior or Sigma/backend readiness; `EventGeneration=Unverified` and `ReadyRuleCredit=0` remain explicit.

Failure before service mutation returns `Refused`; failure after an attempted restart returns `RestartAttemptedUnverified`. Inspect the result and actual service state rather than retrying blindly. If final receipt writing fails, the command fails and the earlier pending receipt may remain; it is not a success record. No automatic rollback occurs. Slow service operations can exceed the subsequent 30-second Running wait; this is not a strict end-to-end restart timeout.

Hashes provide byte consistency, not signature/authorship or protection against a local administrator rewriting all evidence. Path, state and source checks are repeated observations rather than an atomic transaction with Windows or the filesystem. Run from a protected checkout/evidence parent and avoid concurrent administration. The default read-only Plan cannot infer why a prior restart failed or that restarting a production CA is operationally safe.

## Validation

Safe fixtures exercise historical evidence rejection, fresh CA/policy/dependency drift, explicit consent, changed plans, journaling failures, failed/silent restarts, preserved-state verification and replay rejection. Public CLI fixtures also cover the existing `adcs-auditing Configure -DryRun` guard.

The gated disposable CA workflow runs Server 2022/2025 with public CLI calls under PowerShell 5.1/7. A test-only helper refuses the initial restart after real filter writes to produce authentic pending output; this is fault injection, not evidence of a naturally occurring service failure. Separate public child processes then plan, dry-run, perform an actual restart, verify hashed receipts and reject replay. A fixed pending certificate request generates correlated native 4886/4889 afterward. Existing exact audit-policy restoration and owned CA/key/certificate cleanup remain required. Feature removal that requests a reboot relies on disposal of the hosted VM, recorded separately. Enterprise/DC and production maintenance-window acceptance remain outside this fixture.
