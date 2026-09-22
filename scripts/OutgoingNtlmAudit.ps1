# Explicit outgoing audit policy; does not invoke the broad configure workflow.
function Get-WelaOutgoingAuditSnapshot {
    if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess) { throw 'Use 64-bit PowerShell on Windows.' }
    $os=Get-CimInstance Win32_OperatingSystem -Property BuildNumber,ProductType -ErrorAction Stop
    $computer=Get-CimInstance Win32_ComputerSystem -Property DomainRole,PartOfDomain -ErrorAction Stop
    $build=[int]$os.BuildNumber;$product=[int]$os.ProductType
    if (-not (($product -eq 1 -and $build -in @(22000,22621,22631,26100,26200)) -or ($product -in @(2,3) -and $build -in @(20348,26100)))) { throw 'This Windows role/build has not been reviewed for the scoped command.' }
    if ($computer.DomainRole -notin @(0,1,2,3,4,5) -or $computer.PartOfDomain -isnot [bool]) {throw 'Computer role/join context is unavailable.'}
    $policy=Get-WelaRegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' RestrictSendingNTLMTraffic
    if (-not $policy.KeyExists) {throw 'The existing MSV1_0 policy key is required; no parent key will be created.'}
    [pscustomobject][ordered]@{Host=[pscustomobject][ordered]@{Build=$build;ProductType=$product;DomainRole=[int]$computer.DomainRole;PartOfDomain=$computer.PartOfDomain};Policy=$policy}
}

function Get-WelaOutgoingAuditDisposition {
    param($Snapshot,[ValidateSet('PreserveOrAudit','Audit')][string]$Mode)
    $p=$Snapshot.Policy
    if ($p.ValueExists -and ($p.Type -cne 'DWord' -or $p.Value -notin @(0,1,2))) {return 'Unknown'}
    if ($p.ValueExists -and $p.Value -eq 1) {return 'AlreadyCompliant'}
    if ($p.ValueExists -and $p.Value -eq 2 -and $Mode -eq 'PreserveOrAudit') {return 'PreservedEnforcement'}
    return 'ChangeRequired'
}

function Get-WelaOutgoingAuditPlan {
    param([ValidateSet('PreserveOrAudit','Audit')][string]$Mode='PreserveOrAudit')
    try {
        $snapshot=Get-WelaOutgoingAuditSnapshot
        $status=Get-WelaOutgoingAuditDisposition $snapshot $Mode
        $diagnostic=switch($status){
            Unknown {'Unknown registry type/value is preserved; investigate it before configuration.'}
            PreservedEnforcement {'Deny all (2) is authentication enforcement, preserved by default. Explicit -OutgoingNtlmMode Audit authorizes replacing it with Audit all (1).'}
            AlreadyCompliant {'Audit all (1) is configured; authentication, events and policy persistence are unverified.'}
            default {'Set only outgoing NTLM Audit all (DWORD 1).'}
        }
        [pscustomobject]@{Status=$status;Mode=$Mode;Desired=1;Before=$snapshot;Diagnostic=$diagnostic;PolicySource=Get-WelaOutgoingNtlmPolicySource}
    }catch{[pscustomobject]@{Status='Unknown';Mode=$Mode;Desired=1;Before=$null;Diagnostic=$_.ToString();PolicySource='Unknown'}}
}

function Invoke-WelaOutgoingAuditCommand {
    param([ValidateSet('Audit','Plan','Configure')][string]$Action='Audit',[ValidateSet('PreserveOrAudit','Audit')][string]$Mode='PreserveOrAudit',[switch]$Auto,[switch]$DryRun,[string]$BackupPath,[string]$ResultsPath)
    if ($Action -ne 'Configure' -and ($Auto -or $DryRun -or $BackupPath)) {throw 'Consent, dry-run and backup options require Configure.'}
    $plan=Get-WelaOutgoingAuditPlan $Mode
    if ($Action -eq 'Configure') {
        $context=New-WelaConfigurationContext -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath
        $path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0';$name='RestrictSendingNTLMTraffic'
        if ($plan.Status -eq 'Unknown') {
            $context.Results.Add([pscustomobject]@{Id="Registry/$path/$name";Kind='Registry';Target=@{Path=$path;Name=$name};Desired=@{Value=1;Type='DWord'};Before=$plan.Before;After=$null;Status='Failed';Diagnostic=$plan.Diagnostic})
        }else{
            $state=@{Observed=$null;PlannedHost=($plan.Before.Host|ConvertTo-Json -Compress);Mode=$Mode;Path=$path;Name=$name}
            $read={param($s)
                $snapshot=Get-WelaOutgoingAuditSnapshot
                if (($snapshot.Host|ConvertTo-Json -Compress) -cne $s.PlannedHost) {throw 'Observed host context changed; review a new plan.'}
                if ((Get-WelaOutgoingAuditDisposition $snapshot $s.Mode) -eq 'Unknown') {throw 'Unknown registry type/value is preserved.'}
                $s.Observed=$snapshot
                return $snapshot
            }
            $test={param($snapshot) $snapshot.Policy.ValueExists -and $snapshot.Policy.Type -ceq 'DWord' -and $snapshot.Policy.Value -eq 1}
            $preserve=if($Mode -eq 'PreserveOrAudit'){{param($snapshot) if($snapshot.Policy.ValueExists -and $snapshot.Policy.Type -ceq 'DWord' -and $snapshot.Policy.Value -eq 2){'Preserved Deny all enforcement; explicit Audit mode is required to replace it.'}}}else{$null}
            $apply={param($s)
                $fresh=Get-WelaOutgoingAuditSnapshot
                if (($fresh|ConvertTo-Json -Depth 8 -Compress) -cne ($s.Observed|ConvertTo-Json -Depth 8 -Compress)) {throw 'Outgoing NTLM state changed after the original journal snapshot; no write was attempted.'}
                if ((Get-WelaOutgoingAuditDisposition $fresh $s.Mode) -ne 'ChangeRequired') {throw 'The current state no longer authorizes this write.'}
                Set-ItemProperty -LiteralPath $s.Path -Name $s.Name -Value 1 -Type DWord -ErrorAction Stop
                'Only outgoing NTLM Audit all (1) was requested; no authentication or event-generation test was performed.'
            }
            Invoke-WelaConfigurationControl -Context $context -Id "Registry/$path/$name" -Kind Registry -Target @{Path=$path;Name=$name} -Desired @{Value=1;Type='DWord'} -Read $read -Compliant $test -PreserveWhen $preserve -Apply $apply -CallbackState $state -Description $plan.Diagnostic
        }
        $report=Complete-WelaConfiguration -Context $context -Scope 'outgoing-ntlm-audit-policy-only' -SuccessMessage 'Outgoing NTLM configuration results recorded; inspect preserved/skipped controls separately.'
        $report|Add-Member NoteProperty Plan $plan
    }else{$report=[pscustomobject]@{ExitCode=$(if($plan.Status -eq 'Unknown'){1}else{0});Scope='outgoing-ntlm-audit-policy-only';Action=$Action;Plan=$plan}}
    $report|Add-Member NoteProperty EventGeneration 'Not verified; registry compliance does not establish authentication, NTLM events, forwarding, GPO persistence or Sigma readiness.'
    $report|Add-Member NoteProperty ReadyRuleCredit 0
    if ($ResultsPath) {
        try {$report|ConvertTo-Json -Depth 16|Set-Content -LiteralPath $ResultsPath -Encoding UTF8 -ErrorAction Stop}
        catch {$report.ExitCode=1;Write-Host "[Failed] Writing outgoing NTLM results: $_" -ForegroundColor Red}
    }
    return $report
}
