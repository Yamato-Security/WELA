# Explicit native audit-switch activation. No registry policy, security, share or service writes.
function Get-WelaSmbRuntimeKey { param($Value) ConvertTo-Json -InputObject $Value -Depth 24 -Compress }

function Get-WelaSmbRuntimeSources {
    $result=[ordered]@{}
    foreach($name in @('WELA.ps1','scripts/SmbRuntimeActivation.ps1','scripts/SmbAuditing.ps1','scripts/Configuration.ps1','scripts/WefArrival.ps1')) {
        $result[$name]=(Get-FileHash -LiteralPath (Join-Path $script:ScriptRoot $name) -Algorithm SHA256 -ErrorAction Stop).Hash
    }
    [pscustomobject]$result
}

function Get-WelaSmbRuntimeCommands {
    $base=[IO.Path]::GetFullPath((Join-Path $env:windir 'System32/WindowsPowerShell/v1.0/Modules/SmbShare'))
    $commands=[ordered]@{}
    foreach($side in @('Server','Client')) {
        foreach($verb in @('Get','Set')) {
            $name="SmbShare\$verb-Smb${side}Configuration"
            $found=@(Get-Command -Name $name -ErrorAction Stop)
            if($found.Count -ne 1 -or $found[0].ModuleName -cne 'SmbShare' -or
                [IO.Path]::GetFullPath($found[0].Module.ModuleBase) -ine $base) {
                $observed=@($found | ForEach-Object {[pscustomobject]@{Name=$_.Name;ModuleName=$_.ModuleName;ModuleBase=$_.Module.ModuleBase;Type=$_.CommandType.ToString()}})
                throw "SMB commands must resolve to the native Windows SmbShare module. Expected $base; observed $(Get-WelaSmbRuntimeKey $observed)"
            }
            if($verb -eq 'Set') {
                $component=if($side -eq 'Server'){'LanmanServer'}else{'LanmanWorkstation'}
                foreach($definition in @(Get-WelaSmbAuditDefinitions | Where-Object Component -eq $component)) {
                    if(-not $found[0].Parameters.ContainsKey($definition.Name) -or $found[0].Parameters[$definition.Name].ParameterType -ne [bool]) {
                        throw "Native setter lacks the exact Boolean parameter $($definition.Name)."
                    }
                }
            }
            $commands[$name]=[pscustomobject]@{ModuleBase=$base;ModuleVersion=$found[0].Module.Version.ToString();CommandType=$found[0].CommandType.ToString()}
        }
    }
    $files=@(Get-ChildItem -LiteralPath $base -File -Recurse -ErrorAction Stop | Where-Object Extension -in @('.psd1','.psm1','.cdxml','.dll','.ps1xml') | Sort-Object FullName)
    if($files.Count -lt 1 -or $files.Count -gt 100){throw 'Unexpected native SMB module inventory.'}
    $hashes=[ordered]@{}
    foreach($file in $files){
        if($file.Length -gt 16MB -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unsupported SMB module source.'}
        $hashes[$file.FullName]=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
    }
    [pscustomobject]@{Commands=[pscustomobject]$commands;Files=[pscustomobject]$hashes}
}

function ConvertTo-WelaSmbRuntimeConfiguration {
    param($Configuration,[ValidateSet('Server','Client')][string]$Side)
    if($Configuration.CimClass.CimClassName -cne "MSFT_Smb${Side}Configuration"){throw 'Expected one actual native SMB configuration CIM instance.'}
    $properties=@($Configuration.CimInstanceProperties | Sort-Object Name)
    if($properties.Count -lt 3 -or $properties.Count -gt 160){throw 'Unexpected SMB configuration property count.'}
    $result=[ordered]@{}
    foreach($property in $properties) {
        if($result.Contains($property.Name)){throw 'Duplicate SMB configuration property.'}
        $value=$property.Value
        foreach($item in @($value)) {
            if($null -ne $item -and $item -isnot [bool] -and $item -isnot [string] -and
                $item -isnot [byte] -and $item -isnot [uint16] -and $item -isnot [uint32] -and $item -isnot [uint64] -and
                $item -isnot [int16] -and $item -isnot [int32] -and $item -isnot [int64]){throw "Unsupported native configuration value: $($property.Name)"}
            if($item -is [string] -and $item.Length -gt 8192){throw 'Native configuration string exceeds bound.'}
        }
        if(@($value).Count -gt 128){throw 'Native configuration array exceeds bound.'}
        $result[$property.Name]=[pscustomobject]@{CimType=$property.CimType.ToString();Value=$value}
    }
    $component=if($Side -eq 'Server'){'LanmanServer'}else{'LanmanWorkstation'}
    foreach($definition in @(Get-WelaSmbAuditDefinitions | Where-Object Component -eq $component)) {
        if(-not $result.Contains($definition.Name) -or $result[$definition.Name].Value -isnot [bool] -or $result[$definition.Name].CimType -cne 'Boolean') {
            throw "Native getter lacks the exact Boolean property $($definition.Name)."
        }
    }
    [pscustomobject]$result
}

function Get-WelaSmbRuntimeState {
    $hostState=Get-WelaSmbAuditHost
    if($hostState.Status -ne 'Candidate'){throw "SMB runtime activation is $($hostState.Status): $($hostState.Diagnostic)"}
    $commands=Get-WelaSmbRuntimeCommands
    $policies=[ordered]@{}
    foreach($definition in Get-WelaSmbAuditDefinitions) {
        $capability=Get-WelaSmbAuditCapability -Definition $definition -HostState $hostState
        if($capability.Status -ne 'Supported'){throw "Unverified $($definition.Component)/$($definition.Name): $($capability.Diagnostic)"}
        $policies["$($definition.Component)/$($definition.Name)"]=[pscustomobject]@{
            Path=$definition.Path;Name=$definition.Name;AdmxSha256=$capability.AdmxSha256
            Policy=Get-WelaRegistryState -Path $definition.Path -Name $definition.Name
        }
    }
    $configurations=[ordered]@{}
    foreach($side in @('Server','Client')) {
        $command="SmbShare\Get-Smb${side}Configuration"
        $native=@(& $command -ErrorAction Stop)
        if($native.Count -ne 1){throw 'Expected exactly one native SMB configuration.'}
        $configurations[$side]=ConvertTo-WelaSmbRuntimeConfiguration -Configuration $native[0] -Side $side
    }
    [pscustomobject][ordered]@{Computer=[Environment]::MachineName;Host=$hostState;Commands=$commands;Sources=Get-WelaSmbRuntimeSources;Policies=[pscustomobject]$policies;Configurations=[pscustomobject]$configurations}
}

function Get-WelaSmbRuntimePlan {
    param($State)
    foreach($definition in Get-WelaSmbAuditDefinitions) {
        $id="$($definition.Component)/$($definition.Name)"
        $policy=$State.Policies.$id.Policy
        $side=if($definition.Component -eq 'LanmanServer'){'Server'}else{'Client'}
        $value=$State.Configurations.$side.($definition.Name).Value
        $compatible=($policy.ValueExists -is [bool] -and -not $policy.ValueExists) -or
            ($policy.ValueExists -eq $true -and $policy.Type -ceq 'DWord' -and
                ($policy.Value -is [int] -or $policy.Value -is [long] -or $policy.Value -is [uint32]) -and $policy.Value -eq 1)
        [pscustomobject][ordered]@{Id=$id;Side=$side;Name=$definition.Name;Before=$value;Desired=$true;Policy=$policy
            Status=$(if(-not $compatible){'BlockedPolicy'}elseif($value){'AlreadyActive'}else{'ActivationRequired'})
            Diagnostic=$(if(-not $compatible){'Existing policy is not absent or DWORD 1; review its authority. It will not be overwritten.'}elseif($policy.ValueExists){'Policy DWORD 1 and runtime Boolean are separate observations.'}else{'Policy value is absent; explicit activation changes native local configuration only.'})}
    }
}

function Set-WelaSmbRuntimeFlag {
    param([string]$Id)
    $matches=@(Get-WelaSmbAuditDefinitions | Where-Object {"$($_.Component)/$($_.Name)" -ceq $Id})
    if($matches.Count -ne 1){throw 'Unknown SMB audit switch.'}
    $definition=$matches[0]
    $side=if($definition.Component -eq 'LanmanServer'){'Server'}else{'Client'}
    $command="SmbShare\Set-Smb${side}Configuration"
    $parameters=@{Confirm=$false;Force=$true;ErrorAction='Stop'}
    $parameters[$definition.Name]=$true
    $null=& $command @parameters
}

function Write-WelaSmbRuntimeReceipt {
    param([string]$Root,[string]$Name,$Value)
    if($Name -notmatch '^(plan|result|[1-6]-(pending|confirmed))\.json$'){throw 'Unexpected receipt filename.'}
    $null=Resolve-WelaArrivalPath $Root
    $path=Join-Path $Root $Name
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes((Get-WelaSmbRuntimeKey $Value))
    if($bytes.Length -gt 4MB){throw 'SMB activation receipt exceeds bound.'}
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    $expected=Get-WelaArrivalHash $bytes
    if((Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() -cne $expected){throw 'SMB receipt readback differs.'}
    [pscustomobject]@{Name=$Name;Bytes=$bytes.Length;Sha256=$expected}
}

function Invoke-WelaSmbRuntimeActivation {
    param([ValidateSet('Plan','Activate')][string]$Action='Plan',[string]$OutputPath,[switch]$Auto,[switch]$DryRun)
    if($DryRun -and $Action -ne 'Activate'){throw 'DryRun requires SmbRuntimeAction Activate.'}
    if($Action -eq 'Plan' -and ($Auto -or $OutputPath)){throw 'Plan reads only; Auto and OutputPath apply to Activate.'}
    $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaSmbRuntimeActivation';Action=$Action;DryRun=[bool]$DryRun;RecordedUtc=[DateTime]::UtcNow.ToString('o')
        Status='Unverified';ExitCode=1;Before=$null;After=$null;Controls=@();Results=@();Artifacts=@();OutputPath=$null;Diagnostic=''
        VerificationScope='Native local audit switches at the recorded observations; policy authority and persistence are unknown';ReadyRuleCredit=0;EventGeneration='Not tested';Forwarding='Not tested'}
    try {
        $state=Get-WelaSmbRuntimeState;$report.Before=$state
        $report.Controls=@(Get-WelaSmbRuntimePlan $state)
        if(@($report.Controls | Where-Object Status -eq BlockedPolicy).Count){throw 'One or more policy values conflict or are malformed. No audit flags were changed.'}
        if($Action -eq 'Plan' -or $DryRun){$report.Status=if($DryRun){'DryRun'}else{'Planned'};$report.ExitCode=0;return $report}
        if(-not $OutputPath){throw 'Activate requires a new SmbRuntimeOutputPath on a local fixed drive.'}
        $output=New-WelaArrivalOutput -Path $OutputPath -SourcePath $script:ScriptRoot;$report.OutputPath=$output
        $report.Artifacts+=Write-WelaSmbRuntimeReceipt $output 'plan.json' ([pscustomobject]@{State=$state;Controls=$report.Controls})
        $expectedKey=Get-WelaSmbRuntimeKey $state
        $index=0;$stopped=$false
        foreach($control in $report.Controls) {
            $index++
            $row=[pscustomobject][ordered]@{Id=$control.Id;Before=$control.Before;After=$null;Status='Skipped';Diagnostic='';PendingReceipt=$null;ConfirmedReceipt=$null}
            $report.Results+= $row
            if($stopped){$row.Diagnostic='A prior activation failed; no further changes were attempted.';continue}
            try {
                $fresh=Get-WelaSmbRuntimeState
                if((Get-WelaSmbRuntimeKey $fresh) -cne $expectedKey){throw 'Host, source, policy or native configuration drifted after the snapshot.'}
                if($control.Before){$row.After=$true;$row.Status='AlreadyActive';continue}
                if(-not $Auto -and (Read-Host "Activate only SMB audit flag $($control.Id)? (y/N)") -cnotin @('y','Y')){$row.Diagnostic='Declined by operator.';continue}
                $row.PendingReceipt=Write-WelaSmbRuntimeReceipt $output "$index-pending.json" ([pscustomobject]@{Kind='Pending';Id=$control.Id;Before=$fresh;Desired=$true;RecordedUtc=[DateTime]::UtcNow.ToString('o')})
                # Re-read after interaction and durable intent, immediately before the setter.
                if((Get-WelaSmbRuntimeKey (Get-WelaSmbRuntimeState)) -cne $expectedKey){throw 'Context drifted before the native setter; activation refused.'}
                Set-WelaSmbRuntimeFlag -Id $control.Id
                $after=Get-WelaSmbRuntimeState;$row.After=$after.Configurations.($control.Side).($control.Name).Value
                # The only permitted delta is this one Boolean. All policies and every
                # other native configuration property (including security) must match.
                $next=Get-WelaSmbRuntimeKey $fresh | ConvertFrom-Json
                $next.Configurations.($control.Side).($control.Name).Value=$true
                if((Get-WelaSmbRuntimeKey $after) -cne (Get-WelaSmbRuntimeKey $next)){throw 'Native readback did not show exactly the requested audit-only delta.'}
                $row.ConfirmedReceipt=Write-WelaSmbRuntimeReceipt $output "$index-confirmed.json" ([pscustomobject]@{Kind='Confirmed';Id=$control.Id;Pending=$row.PendingReceipt;After=$after;RecordedUtc=[DateTime]::UtcNow.ToString('o')})
                $state=$after;$expectedKey=Get-WelaSmbRuntimeKey $state
                $row.Status='Activated';$row.Diagnostic='Native Boolean True observed; policy tuple and all other configuration properties preserved.'
            }catch{$row.Status='Failed';$row.Diagnostic=$_.Exception.Message;$stopped=$true}
        }
        $report.After=Get-WelaSmbRuntimeState
        if((Get-WelaSmbRuntimeKey $report.After) -cne $expectedKey){throw 'Final context differs from the last verified configuration. Review partial receipts; no automatic rollback is attempted.'}
        if(@($report.Results | Where-Object Status -notin @('Activated','AlreadyActive')).Count){throw 'Some flags were not activated. Inspect per-control results and receipts.'}
        $report.Status='RuntimeAuditingActive';$report.ExitCode=0
    }catch{$report.Diagnostic=$_.Exception.Message}
    if($report.OutputPath){$null=Write-WelaSmbRuntimeReceipt $report.OutputPath 'result.json' $report}
    $report
}
