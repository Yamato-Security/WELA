# Scoped built-in Security 4688 command-line policy. This does not set audit masks.
function Get-WelaProcessCommandlineSnapshot {
    if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess) {throw 'Use 64-bit PowerShell on Windows.'}
    if ((Get-Service Winmgmt -ErrorAction Stop).Status -ne 'Running') {throw 'Existing Windows Management Instrumentation must be running; it will not be started.'}
    $os=Get-CimInstance Win32_OperatingSystem -Property BuildNumber,ProductType -ErrorAction Stop
    $cs=Get-CimInstance Win32_ComputerSystem -Property DomainRole,PartOfDomain -ErrorAction Stop
    $build=[int]$os.BuildNumber;$product=[int]$os.ProductType;$role=[int]$cs.DomainRole
    if ($cs.PartOfDomain -isnot [bool] -or $role -notin 0,1,2,3,4,5 -or
        -not (($product -eq 1 -and $role -in 0,1 -and $build -in 22000,22621,22631,26100,26200) -or
        ($product -eq 2 -and $role -in 4,5 -and $build -in 20348,26100) -or
        ($product -eq 3 -and $role -in 2,3 -and $build -in 20348,26100)) -or
        ($cs.PartOfDomain -ne ($role -in 1,3,4,5))) {throw 'Unknown, unsupported or contradictory Windows role/build/join context.'}
    $path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    $parent=$null;$key=$null
    try {
        $parent=$base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System')
        if (-not $parent) {throw 'The existing System policy parent is required.'}
        $key=$parent.OpenSubKey('Audit')
        $unselected=[pscustomobject][ordered]@{Values=@();Children=@()}
        if ($key) {
            if ($key.ValueCount -gt 128 -or $key.SubKeyCount -gt 128) {throw 'Unrelated policy inventory exceeds its 128-entry bound.'}
            $unselected.Values=@($key.GetValueNames()|Sort-Object|Where-Object {$_ -ine 'ProcessCreationIncludeCmdLine_Enabled'}|ForEach-Object {
                [pscustomobject][ordered]@{Name=$_;Type=$key.GetValueKind($_).ToString();Value=$key.GetValue($_,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}
            })
            $unselected.Children=@($key.GetSubKeyNames()|Sort-Object)
            if (($unselected|ConvertTo-Json -Depth 12 -Compress).Length -gt 1048576) {throw 'Unrelated policy inventory exceeds its one Mi character bound.'}
        }
    } finally {if($key){$key.Dispose()};if($parent){$parent.Dispose()};$base.Dispose()}
    [pscustomobject][ordered]@{
        Host=[pscustomobject][ordered]@{Build=$build;ProductType=$product;DomainRole=$role;PartOfDomain=$cs.PartOfDomain}
        Policy=Get-WelaRegistryState $path ProcessCreationIncludeCmdLine_Enabled
        Unselected=$unselected
    }
}

function Get-WelaProcessCommandlineDisposition {
    param($Snapshot)
    $p=$Snapshot.Policy
    if ($p.ValueExists -and ($p.Type -cne 'DWord' -or $p.Value -notin 0,1)) {return 'Unknown'}
    if ($p.ValueExists -and $p.Value -eq 1) {return 'AlreadyCompliant'}
    return 'ChangeRequired'
}

function Get-WelaProcessCommandlinePrerequisite {
    try {
        $m=Get-WelaEffectiveAuditPolicy;$guid='0cce922b-69ae-11d9-bed3-505054503030'
        if (-not $m.ContainsKey($guid) -or $m[$guid] -notin 0,1,2,3) {throw 'Process Creation mask is unavailable.'}
        [pscustomobject]@{State=$(if($m[$guid] -band 1){'SuccessEnabled'}else{'SuccessMissing'});Mask=$m[$guid];Precedence=Get-WelaRegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' SCENoApplyLegacyAuditPolicy;Diagnostic='Observed only. This command does not change audit policy or precedence.'}
    } catch {[pscustomobject]@{State='Unknown';Mask=$null;Precedence=$null;Diagnostic=$_.ToString()}}
}

function Get-WelaProcessCommandlinePlan {
    try {
        $snapshot=Get-WelaProcessCommandlineSnapshot
        $status=Get-WelaProcessCommandlineDisposition $snapshot
        [pscustomobject]@{Status=$status;Before=$snapshot;Desired=1;Prerequisite=Get-WelaProcessCommandlinePrerequisite;PolicySource='Unknown: local registry observation does not identify the winning GPO or MDM policy.';Diagnostic=$(if($status -eq 'Unknown'){'Unknown registry type/value is preserved.'}else{'Enable only the Security 4688 command-line DWORD. Arguments are recorded as plain text and may contain sensitive data.'})}
    } catch {[pscustomobject]@{Status='Unknown';Before=$null;Desired=1;Prerequisite=$null;PolicySource='Unknown';Diagnostic=$_.ToString()}}
}

function Invoke-WelaProcessCommandline {
    param([ValidateSet('Audit','Plan','Configure')][string]$Action='Audit',[switch]$Auto,[switch]$DryRun,[string]$BackupPath,[string]$ResultsPath)
    if ($Action -ne 'Configure' -and ($Auto -or $DryRun -or $BackupPath)) {throw 'Consent, dry-run and backup options require Configure.'}
    $plan=Get-WelaProcessCommandlinePlan
    if ($Action -eq 'Configure') {
        $context=New-WelaConfigurationContext -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath
        $path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit';$name='ProcessCreationIncludeCmdLine_Enabled'
        if ($plan.Status -eq 'Unknown') {
            $context.Results.Add([pscustomobject]@{Id="Registry/$path/$name";Kind='Registry';Target=@{Path=$path;Name=$name};Desired=@{Value=1;Type='DWord'};Before=$plan.Before;After=$null;Status='Failed';Diagnostic=$plan.Diagnostic})
        } else {
            $state=@{Observed=$null;Planned=($plan.Before|ConvertTo-Json -Depth 12 -Compress);Preserved=([ordered]@{Host=$plan.Before.Host;Unselected=$plan.Before.Unselected}|ConvertTo-Json -Depth 12 -Compress);Path=$path;Name=$name;First=$true}
            $read={param($s)
                $snapshot=Get-WelaProcessCommandlineSnapshot
                if ((Get-WelaProcessCommandlineDisposition $snapshot) -eq 'Unknown') {throw 'Unknown registry type/value is preserved.'}
                if (([ordered]@{Host=$snapshot.Host;Unselected=$snapshot.Unselected}|ConvertTo-Json -Depth 12 -Compress) -cne $s.Preserved) {throw 'Host or unrelated policy values/subkeys changed; review a new plan.'}
                if ($s.First -and ($snapshot|ConvertTo-Json -Depth 12 -Compress) -cne $s.Planned) {throw 'Policy changed after planning; review a new plan.'}
                $s.First=$false;$s.Observed=$snapshot;return $snapshot
            }
            $test={param($snapshot) $snapshot.Policy.ValueExists -and $snapshot.Policy.Type -ceq 'DWord' -and $snapshot.Policy.Value -eq 1}
            $apply={param($s)
                $fresh=Get-WelaProcessCommandlineSnapshot
                if (($fresh|ConvertTo-Json -Depth 12 -Compress) -cne ($s.Observed|ConvertTo-Json -Depth 12 -Compress)) {throw 'Policy changed after its original journal; no write attempted.'}
                if ((Get-WelaProcessCommandlineDisposition $fresh) -ne 'ChangeRequired') {throw 'Current state no longer authorizes this write.'}
                if (-not $fresh.Policy.KeyExists) {$null=New-WelaRegistryKey -Path $s.Path}
                Set-ItemProperty -LiteralPath $s.Path -Name $s.Name -Value 1 -Type DWord -ErrorAction Stop
                'Requested only command-line inclusion. Process Creation success auditing remains a separate prerequisite.'
            }
            Invoke-WelaConfigurationControl -Context $context -Id "Registry/$path/$name" -Kind Registry -Target @{Path=$path;Name=$name} -Desired @{Value=1;Type='DWord'} -Read $read -Compliant $test -Apply $apply -CallbackState $state -Description $plan.Diagnostic
        }
        $report=Complete-WelaConfiguration -Context $context -Scope 'process-commandline-policy-only' -SuccessMessage 'Command-line policy results recorded; inspect prerequisites and skipped controls separately.'
        $report|Add-Member NoteProperty Plan $plan
    } else {$report=[pscustomobject]@{ExitCode=$(if($plan.Status -eq 'Unknown'){1}else{0});Action=$Action;Scope='process-commandline-policy-only';Plan=$plan}}
    $report|Add-Member NoteProperty EventGeneration 'Unverified: policy readback is not 4688, field, forwarding, GPO persistence or complete-rule evidence.'
    $report|Add-Member NoteProperty ReadyRuleCredit 0
    if ($ResultsPath) {try {$report|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $ResultsPath -Encoding UTF8 -ErrorAction Stop}catch{$report.ExitCode=1;Write-Host "[Failed] Writing command-line policy results: $_" -ForegroundColor Red}}
    return $report
}
