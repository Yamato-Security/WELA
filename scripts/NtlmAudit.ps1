# Explicit incoming/domain audit values. Authentication restrictions are separate controls.
function Get-WelaNtlmAuditHost {
    if($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess){throw 'Use native64-bit PowerShell on Windows.'}
    $os=Get-CimInstance Win32_OperatingSystem -Property BuildNumber,ProductType -ErrorAction Stop
    $computer=Get-CimInstance Win32_ComputerSystem -Property Name,Domain,DomainRole,PartOfDomain -ErrorAction Stop
    if([string]$os.BuildNumber -notmatch '^\d+$' -or $os.ProductType -notin @(1,2,3) -or $computer.PartOfDomain -isnot [bool] -or $computer.DomainRole -notin @(0,1,2,3,4,5) -or [string]::IsNullOrWhiteSpace($computer.Name)){throw 'Incomplete Windows role/build identity.'}
    $build=[int]$os.BuildNumber;$product=[int]$os.ProductType;$role=[int]$computer.DomainRole;$joined=$computer.PartOfDomain
    $coherent=($product -eq 1 -and (($role -eq 0 -and -not $joined) -or ($role -eq 1 -and $joined))) -or ($product -eq 3 -and (($role -eq 2 -and -not $joined) -or ($role -eq 3 -and $joined))) -or ($product -eq 2 -and $role -in @(4,5) -and $joined)
    if(-not $coherent){throw 'Conflicting native product/domain-role/join observations.'}
    if(-not (($product -eq 1 -and $build -in @(22000,22621,22631,26100,26200)) -or ($product -in @(2,3) -and $build -in @(20348,26100)))){throw 'This Windows role/build has not been reviewed.'}
    [pscustomobject][ordered]@{Computer=[string]$computer.Name;Domain=[string]$computer.Domain;Build=$build;ProductType=$product;DomainRole=$role;PartOfDomain=$joined}
}
function Get-WelaNtlmAuditDefinition {
    param([ValidateSet('Incoming','Domain')][string]$Selection)
    if($Selection -eq 'Incoming'){return [pscustomobject]@{Selection='Incoming';Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0';Name='AuditReceivingNTLMTraffic';Value=2;Known=@(0,1,2);Meaning='Enable auditing for all accounts'}}
    [pscustomobject]@{Selection='Domain';Path='HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters';Name='AuditNTLMInDomain';Value=7;Known=@(0,1,2,3,5,7);Meaning='Enable all domain NTLM auditing on the observed domain controller'}
}
function Get-WelaNtlmAuditSnapshot {
    param([ValidateSet('Incoming','Domain')][string]$Selection)
    $observedHost=Get-WelaNtlmAuditHost
    if($Selection -eq 'Domain' -and $observedHost.ProductType -ne 2){return [pscustomobject][ordered]@{Host=$observedHost;Applicable=$false;Policy=$null}}
    $definition=Get-WelaNtlmAuditDefinition $Selection
    $policy=Get-WelaRegistryState $definition.Path $definition.Name
    if(-not $policy.KeyExists){throw 'The existing native policy key is required; no parent key will be created.'}
    [pscustomobject][ordered]@{Host=$observedHost;Applicable=$true;Policy=$policy}
}
function Get-WelaNtlmAuditDisposition {
    param($Snapshot,$Definition)
    if(-not $Snapshot.Applicable){return 'NotApplicable'}
    $p=$Snapshot.Policy
    if($p.ValueExists -and ($p.Type -cne 'DWord' -or ($p.Value -isnot [int] -and $p.Value -isnot [long] -and $p.Value -isnot [uint32]) -or $p.Value -notin $Definition.Known)){return 'Unknown'}
    if($p.ValueExists -and $p.Value -eq $Definition.Value){return 'AlreadyCompliant'}
    if($Definition.Selection -eq 'Domain' -and $p.ValueExists -and $p.Value -eq 2){return 'LegacyValue2'}
    return 'ChangeRequired'
}
function Get-WelaNtlmAuditPolicySource {
    param($Definition)
    $key='MACHINE\'+$Definition.Path.Substring(6)
    try{
        $rows=@(Get-CimInstance -Namespace 'root\RSOP\Computer' -ClassName RSOP_RegistryValue -ErrorAction Stop|Where-Object {$_.KeyName -ieq $key -and $_.ValueName -ieq $Definition.Name}|Sort-Object precedence)
        [pscustomobject]@{Status=$(if($rows.Count){'Observed'}else{'NotObserved'});Class='RSOP_RegistryValue';Matches=@($rows|Select-Object KeyName,ValueName,Type,Data,GPOID,precedence);Diagnostic='Last-applied RSoP may be stale or incomplete. This does not establish the current registry writer, local ownership or policy persistence.'}
    }catch{[pscustomobject]@{Status='Unknown';Class='RSOP_RegistryValue';Matches=@();Diagnostic=$_.Exception.Message+' RSoP is potentially stale and is not current policy ownership evidence.'}}
}
function Get-WelaNtlmAuditPlan {
    param([ValidateSet('Incoming','Domain','Both')][string]$Selection='Both')
    $rows=@()
    foreach($selected in @($(if($Selection -eq 'Both'){'Incoming';'Domain'}else{$Selection}))){
        $definition=Get-WelaNtlmAuditDefinition $selected
        try{
            $snapshot=Get-WelaNtlmAuditSnapshot $selected;$status=Get-WelaNtlmAuditDisposition $snapshot $definition
            $diagnostic=switch($status){
                NotApplicable {'Domain NTLM auditing is not applicable to this observed non-DC host. No domain policy value was read or selected for writing.'}
                Unknown {'Unknown registry type/value is preserved. Inspect it before configuration.'}
                LegacyValue2 {'Historical WELA value2 is not credited as Enable all. Its undocumented meaning is not inferred; selected Configure requests DWORD7.'}
                AlreadyCompliant {'The requested audit value is configured. Actual authentication events and policy persistence are unverified.'}
                default {$definition.Meaning}
            }
            $rows+=[pscustomobject]@{Selection=$selected;Definition=$definition;Status=$status;Before=$snapshot;Diagnostic=$diagnostic;PolicySource=$(if($snapshot.Applicable){Get-WelaNtlmAuditPolicySource $definition}else{$null})}
        }catch{$rows+=[pscustomobject]@{Selection=$selected;Definition=$definition;Status='Unknown';Before=$null;Diagnostic=$_.ToString();PolicySource=$null}}
    }
    [pscustomobject]@{Selection=$Selection;Controls=$rows;Mode='Audit only';PlanKind='Live assessment; not an importable authorization file'}
}
function Invoke-WelaNtlmAuditCommand {
    param([ValidateSet('Audit','Plan','Configure')][string]$Action='Audit',[ValidateSet('Incoming','Domain','Both')][string]$Selection='Both',[switch]$Auto,[switch]$DryRun,[string]$BackupPath,[string]$ResultsPath)
    if($Action -ne 'Configure' -and ($Auto -or $DryRun -or $BackupPath)){throw 'Consent, dry-run and backup options require Configure.'}
    if($Action -eq 'Configure' -and -not $PSBoundParameters.ContainsKey('Selection')){throw 'Configure requires an explicit Incoming, Domain or Both selection.'}
    $plan=Get-WelaNtlmAuditPlan $Selection
    if($Action -eq 'Configure'){
        $context=New-WelaConfigurationContext -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath
        foreach($row in $plan.Controls){
            $definition=$row.Definition;$target=@{Path=$definition.Path;Name=$definition.Name};$desired=@{Value=$definition.Value;Type='DWord'};$id="Registry/$($definition.Path)/$($definition.Name)"
            if($row.Status -in @('Unknown','NotApplicable')){
                $context.Results.Add([pscustomobject]@{Id=$id;Kind='Registry';Target=$target;Desired=$desired;Before=$row.Before;After=$null;Status=$(if($row.Status -eq 'Unknown'){'Failed'}else{'Skipped'});Diagnostic=$row.Diagnostic})
                continue
            }
            $state=@{Observed=$null;PlannedHost=($row.Before.Host|ConvertTo-Json -Compress);Definition=$definition}
            $read={param($s)
                $snapshot=Get-WelaNtlmAuditSnapshot $s.Definition.Selection
                if(($snapshot.Host|ConvertTo-Json -Compress) -cne $s.PlannedHost -or -not $snapshot.Applicable){throw 'Native host role/context changed; review a new plan.'}
                if((Get-WelaNtlmAuditDisposition $snapshot $s.Definition) -eq 'Unknown'){throw 'Unknown registry type/value is preserved.'}
                $s.Observed=$snapshot;return $snapshot
            }
            $test={param($snapshot,$s) $snapshot.Applicable -and $snapshot.Policy.ValueExists -and $snapshot.Policy.Type -ceq 'DWord' -and $snapshot.Policy.Value -eq $s.Definition.Value}
            $apply={param($s)
                $fresh=Get-WelaNtlmAuditSnapshot $s.Definition.Selection
                if(($fresh|ConvertTo-Json -Depth 8 -Compress) -cne ($s.Observed|ConvertTo-Json -Depth 8 -Compress)){throw 'NTLM audit state changed after the original journal snapshot; no write attempted.'}
                if((Get-WelaNtlmAuditDisposition $fresh $s.Definition) -notin @('ChangeRequired','LegacyValue2')){throw 'The current state no longer authorizes this write.'}
                Set-ItemProperty -LiteralPath $s.Definition.Path -Name $s.Definition.Name -Value $s.Definition.Value -Type DWord -ErrorAction Stop
                'Only the selected NTLM audit DWORD was requested. Authentication restrictions and exceptions were not changed.'
            }
            Invoke-WelaConfigurationControl -Context $context -Id $id -Kind Registry -Target $target -Desired $desired -Read $read -Compliant $test -Apply $apply -CallbackState $state -Description $row.Diagnostic
        }
        $report=Complete-WelaConfiguration -Context $context -Scope 'incoming-domain-ntlm-audit-policy-only' -SuccessMessage 'Selected NTLM audit results recorded; inspect failed/skipped controls separately.'
        $report|Add-Member NoteProperty Plan $plan
    }else{$report=[pscustomobject]@{ExitCode=$(if(@($plan.Controls|Where-Object Status -eq 'Unknown').Count){1}else{0});Scope='incoming-domain-ntlm-audit-policy-only';Action=$Action;Plan=$plan}}
    $report|Add-Member NoteProperty EventGeneration 'Unverified. Audit registry values do not prove authentication, NTLM events, GPO persistence, forwarding or Sigma readiness.'
    $report|Add-Member NoteProperty ReadyRuleCredit 0
    if($ResultsPath){try{$report|ConvertTo-Json -Depth 18|Set-Content -LiteralPath $ResultsPath -Encoding UTF8 -ErrorAction Stop}catch{$report.ExitCode=1;Write-Host "[Failed] Writing NTLM audit results: $_" -ForegroundColor Red}}
    return $report
}
