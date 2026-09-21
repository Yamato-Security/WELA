# Explicit recovery of one completed Windows PowerShell transcription policy write.
function Copy-WelaTranscriptRecoveryValue {
    param($Value)
    # Windows PowerShell 5.1 annotates a root array emitted by ConvertFrom-Json;
    # serializing that annotated array can introduce synthetic value/count keys.
    # Keep arrays nested during the JSON roundtrip and emit their actual items.
    $holder=ConvertFrom-WelaRecoveryJson (Get-WelaRecoveryKey ([pscustomobject]@{Data=$Value}))
    $holder.Data
}
function Get-WelaTranscriptRecoverySources {
    $sources=[ordered]@{}
    foreach($name in @('WELA.ps1','scripts/TranscriptionRecovery.ps1','scripts/PowerShellTranscription.ps1','scripts/Configuration.ps1','scripts/AuditRecovery.ps1','scripts/ControlApplicability.ps1','scripts/ChannelRead.ps1','scripts/ChannelReadNative.cs','scripts/WefArrival.ps1')) {
        $sources[$name]=(Get-FileHash -LiteralPath (Join-Path $script:ScriptRoot $name) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    }
    [pscustomobject]$sources
}
function Get-WelaTranscriptRecoveryContext {
    $hostState=Get-WelaRecoveryHost
    $reader=Get-WelaChannelReader
    if(-not $reader.ElevatedAdministrator){throw 'Transcription recovery requires an elevated administrator primary token.'}
    # A reviewed plan can be consumed by a new process in the same logon session.
    [pscustomobject][ordered]@{Host=$hostState;Reader=($reader|Select-Object UserSid,UserName,AuthenticationId,GroupSids,ElevatedAdministrator,TokenType,Impersonation)}
}
function Assert-WelaTranscriptRecoveryLocalPath {
    param([string]$Path)
    Test-WelaTranscriptDirectoryPath $Path
    if($Path -notmatch '^[A-Za-z]:\\' -or (Get-WelaRecoveryOutputDriveType ([IO.Path]::GetPathRoot($Path))) -ne [IO.DriveType]::Fixed){throw 'Transcription recovery supports ordinary local fixed-drive paths only; UNC and mapped drives require manual recovery.'}
}
function Read-WelaTranscriptRecoveryFile {
    param([string]$Path)
    Assert-WelaTranscriptRecoveryLocalPath $Path
    Get-WelaRecoveryFile $Path
}
function Get-WelaTranscriptRecoveryProtectedPolicy {
    # Inventory the complete PowerShell policy tree, excluding only the two owned
    # machine values. No policy, header, module/script-block or user writes occur.
    $rows=New-Object 'System.Collections.Generic.List[object]'
    foreach($hive in @('LocalMachine','CurrentUser')) {
        $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::$hive,[Microsoft.Win32.RegistryView]::Registry64)
        try {
            $queue=New-Object 'System.Collections.Generic.Queue[string]';$queue.Enqueue('')
            while($queue.Count) {
                $relative=$queue.Dequeue();$path='SOFTWARE\Policies\Microsoft\Windows\PowerShell'+$relative
                $key=$base.OpenSubKey($path,$false)
                try {
                    $values=@();$children=@()
                    if($null -ne $key) {
                        $children=@($key.GetSubKeyNames()|Sort-Object)
                        foreach($name in ($key.GetValueNames()|Sort-Object)) {
                            if($hive -eq 'LocalMachine' -and $relative -eq '\Transcription' -and $name -in @('EnableTranscripting','OutputDirectory')){continue}
                            $values += [pscustomobject][ordered]@{Name=$name;Type=$key.GetValueKind($name).ToString();Value=$key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}
                        }
                    }
                    $rows.Add([pscustomobject][ordered]@{Hive=$hive;Path=$relative;Exists=($null -ne $key);Values=$values;Children=$children})
                    if($rows.Count -gt 128 -or $queue.Count+$children.Count -gt 128 -or $relative.Length -gt 1024 -or $values.Count -gt 256){throw 'PowerShell policy inventory exceeded bounded recovery scope.'}
                    foreach($child in $children){$queue.Enqueue($relative+'\'+$child)}
                } finally {if($key){$key.Dispose()}}
            }
        } finally {$base.Dispose()}
    }
    $result=@($rows.ToArray())
    if((Get-WelaRecoveryKey $result).Length -gt 1048576){throw 'PowerShell policy inventory exceeded 1 MiB.'}
    return ,$result
}
function Assert-WelaTranscriptRecoveryValue {
    param($Value,[string]$Name)
    if($null -eq $Value -or $Value.KeyExists -isnot [bool] -or $Value.ValueExists -isnot [bool]){throw 'Missing typed transcription value state.'}
    if(-not $Value.ValueExists) {
        if($null -ne $Value.Type -or $null -ne $Value.Value){throw 'Absent transcription value has inconsistent state.'}
    } elseif(-not $Value.KeyExists){throw 'A present transcription value requires an existing key.'}
    elseif($Name -eq 'EnableTranscripting') {
        if($Value.Type -cne 'DWord' -or ($Value.Value -isnot [int] -and $Value.Value -isnot [long]) -or $Value.Value -notin @(0,1)){throw 'Only DWORD 0/1 or absent enablement can be restored; other types require manual recovery.'}
    } elseif($Value.Type -cne 'String' -or $Value.Value -isnot [string] -or -not $Value.Value){throw 'Only a nonempty REG_SZ or absent output directory can be restored.'}
}
function Get-WelaTranscriptRecoveryTypedKey {
    param($Value)
    Get-WelaRecoveryKey ($Value|Select-Object ValueExists,Type,Value)
}
function Get-WelaTranscriptRecoveryDestinations {
    param([string[]]$Paths)
    foreach($path in ($Paths|Sort-Object -Unique)) {
        Assert-WelaTranscriptRecoveryLocalPath $path
        $directory=Get-WelaTranscriptDestination $path
        if(-not $directory.ConfigureAllowed -or $directory.Status -cne 'Observed'){throw "Recovery destination cannot be verified: $($directory.Diagnostic)"}
        $directory
    }
}
function New-WelaTranscriptRecoveryPlan {
    param([string]$JournalPath,[string]$OriginalResultsPath)
    $context=Get-WelaTranscriptRecoveryContext;$sources=Get-WelaTranscriptRecoverySources
    $journal=Read-WelaTranscriptRecoveryFile $JournalPath;$resultFile=Read-WelaTranscriptRecoveryFile $OriginalResultsPath
    $entries=@($journal.Text -split '\r?\n'|Where-Object {$_ -match '\S'}|ForEach-Object {ConvertFrom-WelaRecoveryJson $_})
    $results=ConvertFrom-WelaRecoveryJson $resultFile.Text
    if($entries.Count -ne 1 -or $results.Results -isnot [array] -or $results.Results.Count -ne 1 -or $results.DryRun -isnot [bool] -or $results.DryRun -or
       $results.ExitCode -ne 0 -or $results.Failed -ne 0 -or $results.Skipped -ne 0 -or $results.Action -cne 'Configure' -or $results.Scope -cne 'windows-powershell-transcription-policy-only'){throw 'Recovery requires one completed Applied transcription Configure journal/result, without other controls or partial outcomes.'}
    $entry=$entries[0];$last=$results.Results[0]
    if($entry.Version -ne 1 -or $entry.ComputerName -isnot [string] -or $entry.ComputerName -ine $context.Host.Computer -or $entry.Id -cne 'PowerShellTranscription/CisV4L2' -or
       $entry.Kind -cne 'PowerShellTranscription' -or $last.Status -cne 'Applied' -or $last.Id -cne $entry.Id -or $last.Kind -cne $entry.Kind){throw 'Wrong host, control, schema or incomplete transcription history.'}
    $time=[datetimeoffset]::MinValue
    if($entry.RecordedUtc -isnot [string] -or $entry.RecordedUtc -notmatch '(Z|\+00:00)$' -or -not [datetimeoffset]::TryParse($entry.RecordedUtc,[ref]$time) -or $time -gt [datetimeoffset]::UtcNow.AddMinutes(1)){throw 'Original journal requires a valid UTC timestamp.'}
    foreach($field in @('Before','Target','Desired')){if((Get-WelaRecoveryKey $entry.$field) -cne (Get-WelaRecoveryKey $last.$field)){throw "Original journal/result $field differs."}}
    if($entry.Target.Hive -cne 'LocalMachine' -or $entry.Target.SubKey -cne 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -or $entry.Desired.EnableTranscripting.Type -cne 'DWord' -or $entry.Desired.EnableTranscripting.Value -ne 1 -or
       $entry.Desired.OutputDirectory.Type -cne 'String' -or $entry.Desired.OutputDirectory.Value -cne $entry.Target.OutputDirectory -or $entry.Desired.EnableInvocationHeader -cne 'Preserve'){throw 'Unsupported transcription target or desired state.'}
    $before=$entry.Before;$after=$last.After
    foreach($snapshot in @($before,$after)) {
        if($snapshot.Capability.Status -cne 'Supported' -or $snapshot.Policy -isnot [array] -or $snapshot.Policy.Count -ne 2 -or
           $snapshot.Policy[0].View -cne 'Registry64' -or $snapshot.Policy[1].View -cne 'Registry32'){
            $policyType=if($null -eq $snapshot.Policy){'<null>'}else{$snapshot.Policy.GetType().FullName}
            throw "Both canonical shared registry views are required. Capability=$($snapshot.Capability.Status); PolicyType=$policyType; Count=$(@($snapshot.Policy).Count); Views=$(@($snapshot.Policy.View) -join ','); Observation=$(Get-WelaRecoveryKey $snapshot)"
        }
        Test-WelaTranscriptSharedPolicy $snapshot.Policy
        foreach($name in @('EnableTranscripting','OutputDirectory')){Assert-WelaTranscriptRecoveryValue $snapshot.Policy[0].Machine.$name $name}
    }
    if(-not (Test-WelaTranscriptConfigured $after $entry.Target.OutputDirectory)){throw 'Final transcription policy was not the requested enabled state.'}
    if((Get-WelaRecoveryKey $before.Policy[0].CurrentUser) -cne (Get-WelaRecoveryKey $after.Policy[0].CurrentUser) -or
       (Get-WelaTranscriptRecoveryTypedKey $before.Policy[0].Machine.EnableInvocationHeader) -cne (Get-WelaTranscriptRecoveryTypedKey $after.Policy[0].Machine.EnableInvocationHeader)){throw 'Original configuration did not preserve user/header policy.'}
    $current=Get-WelaTranscriptState $entry.Target.OutputDirectory
    if((Get-WelaRecoveryKey $current.Policy) -cne (Get-WelaRecoveryKey $after.Policy) -or (Get-WelaRecoveryKey $current.Destination) -cne (Get-WelaRecoveryKey $after.Destination)){throw 'Current policy/destination differs from the original final After state.'}
    $target=Copy-WelaTranscriptRecoveryValue $after.Policy
    foreach($view in $target){foreach($name in @('EnableTranscripting','OutputDirectory')) {
        $view.Machine.$name=Copy-WelaTranscriptRecoveryValue $before.Policy[0].Machine.$name
        # Keep the existing key; absence recovery removes only the selected value.
        $view.Machine.$name.KeyExists=$true
    }}
    $prior=$before.Policy[0].Machine;$paths=@([string]$entry.Target.OutputDirectory)
    if($prior.OutputDirectory.ValueExists){$paths += [string]$prior.OutputDirectory.Value}
    elseif(-not ($prior.EnableTranscripting.ValueExists -and $prior.EnableTranscripting.Value -eq 0)) {
        throw 'Restoring an absent output directory requires explicit prior DWORD 0; user/default destinations require manual recovery.'
    }
    $directories=@(Get-WelaTranscriptRecoveryDestinations $paths)
    $outputChanges=(Get-WelaTranscriptRecoveryTypedKey $prior.OutputDirectory) -cne (Get-WelaTranscriptRecoveryTypedKey $after.Policy[0].Machine.OutputDirectory)
    $suspend=$outputChanges -and -not ($prior.EnableTranscripting.ValueExists -and $prior.EnableTranscripting.Value -eq 0)
    $steps=New-Object 'System.Collections.Generic.List[object]'
    if($outputChanges) {
        $off=if($suspend){[pscustomobject]@{KeyExists=$true;ValueExists=$true;Value=0;Type='DWord'}}else{$target[0].Machine.EnableTranscripting}
        $steps.Add([pscustomobject]@{Name='EnableTranscripting';Value=$off;Purpose=$(if($suspend){'Explicit temporary suspension'}else{'Restore disabled state before destination'})})
        $steps.Add([pscustomobject]@{Name='OutputDirectory';Value=$target[0].Machine.OutputDirectory;Purpose='Restore original destination value or absence'})
        if($suspend){$steps.Add([pscustomobject]@{Name='EnableTranscripting';Value=$target[0].Machine.EnableTranscripting;Purpose='Restore original enablement value or absence'})}
    } elseif((Get-WelaTranscriptRecoveryTypedKey $prior.EnableTranscripting) -cne (Get-WelaTranscriptRecoveryTypedKey $after.Policy[0].Machine.EnableTranscripting)) {
        $steps.Add([pscustomobject]@{Name='EnableTranscripting';Value=$target[0].Machine.EnableTranscripting;Purpose='Restore original enablement value or absence'})
    }
    if(-not $steps.Count){throw 'Original Applied evidence contains no recoverable typed changes.'}
    $protected=Get-WelaTranscriptRecoveryProtectedPolicy
    [pscustomobject][ordered]@{Kind='WelaTranscriptionRecoveryPlan';SchemaVersion=1;Context=$context;Sources=$sources;
        Journal=[pscustomobject]@{Path=$journal.Path;Sha256=$journal.Sha256};OriginalResults=[pscustomobject]@{Path=$resultFile.Path;Sha256=$resultFile.Sha256};
        ExpectedPolicy=$after.Policy;RecoverTo=$target;Directories=$directories;ProtectedPolicy=$protected;RequiresTemporarySuspension=[bool]$suspend;Steps=@($steps.ToArray());
        HistoricalIdentity='Version-1 configuration journals record ComputerName only. Current host/reader/code bindings do not authenticate historical identity or evidence.';SigmaEvtxCredit=0}
}
function Assert-WelaTranscriptRecoveryBindings {
    param($Plan,$Policy,[string]$PlanPath,[string]$PlanHash)
    foreach($source in @($Plan.Journal,$Plan.OriginalResults)){if((Read-WelaTranscriptRecoveryFile $source.Path).Sha256 -cne $source.Sha256){throw 'Original transcription recovery evidence changed.'}}
    if($PlanPath -and (Read-WelaTranscriptRecoveryFile $PlanPath).Sha256 -cne $PlanHash){throw 'Reviewed transcription recovery plan changed.'}
    if((Get-WelaRecoveryKey (Get-WelaTranscriptRecoveryContext)) -cne (Get-WelaRecoveryKey $Plan.Context) -or (Get-WelaRecoveryKey (Get-WelaTranscriptRecoverySources)) -cne (Get-WelaRecoveryKey $Plan.Sources)){throw 'Actual host, reader or recovery implementation changed.'}
    if((Get-WelaRecoveryKey (Get-WelaTranscriptRecoveryProtectedPolicy)) -cne (Get-WelaRecoveryKey $Plan.ProtectedPolicy)){throw 'Preserved PowerShell policy changed; recovery stopped.'}
    if((Get-WelaRecoveryKey @(Get-WelaTranscriptRecoveryDestinations @($Plan.Directories.RequestedPath))) -cne (Get-WelaRecoveryKey $Plan.Directories)){throw 'A reviewed transcript directory changed.'}
    $capability=Get-WelaTranscriptCapability
    if($capability.Status -cne 'Supported'){throw 'Windows PowerShell capability changed.'}
    $current=@(Get-WelaTranscriptPolicy $capability.Views);Test-WelaTranscriptSharedPolicy $current
    if((Get-WelaRecoveryKey $current) -cne (Get-WelaRecoveryKey $Policy)){throw 'Current typed transcription policy drifted from the expected recovery step.'}
}
function Set-WelaTranscriptRecoveryValue {
    param([ValidateSet('EnableTranscripting','OutputDirectory')][string]$Name,$Value)
    Assert-WelaTranscriptRecoveryValue $Value $Name
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    $key=$null
    try {
        $key=$base.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription',$true)
        if($null -eq $key){throw 'Existing transcription key disappeared; it will not be recreated.'}
        if($Value.ValueExists){$key.SetValue($Name,$Value.Value,[Microsoft.Win32.RegistryValueKind]([string]$Value.Type))}
        else{$key.DeleteValue($Name,$false)}
        $key.Flush()
    } finally {if($key){$key.Dispose()};$base.Dispose()}
}
function Write-WelaTranscriptRecoveryArtifact {
    param($Directory,[string]$Name,$Value)
    $fresh=Get-WelaTranscriptDestination $Directory.RequestedPath
    if(-not $fresh.ConfigureAllowed -or (Get-WelaRecoveryKey $fresh) -cne (Get-WelaRecoveryKey $Directory)){throw 'Private recovery output directory changed.'}
    Write-WelaRecoveryArtifact (Join-Path $Directory.Path $Name) $Value
}
function Invoke-WelaTranscriptRecovery {
    param([ValidateSet('Plan','Restore')][string]$Action='Plan',[string]$JournalPath,[string]$OriginalResultsPath,[string]$PlanPath,[string]$PlanHash,[string]$OutputPath,[switch]$AllowTemporarySuspension,[switch]$Auto,[switch]$DryRun)
    $ErrorActionPreference='Stop'
    if($Action -eq 'Plan') {
        if($PlanPath -or $PlanHash -or $Auto -or $DryRun -or $AllowTemporarySuspension){throw 'Plan takes original journal/results and new output only; consent flags are Restore-only.'}
        $plan=New-WelaTranscriptRecoveryPlan $JournalPath $OriginalResultsPath
        Assert-WelaTranscriptRecoveryBindings $plan $plan.ExpectedPolicy
        Assert-WelaTranscriptRecoveryLocalPath $OutputPath
        $output=New-WelaRecoveryOutput $OutputPath
        $outputObservation=Get-WelaTranscriptDestination $output
        Write-WelaTranscriptRecoveryArtifact $outputObservation 'plan.json' $plan
        $hash=(Read-WelaTranscriptRecoveryFile (Join-Path $output 'plan.json')).Sha256
        return [pscustomobject]@{Status='Planned';ExitCode=0;OutputPath=$output;PlanSha256=$hash;RequiresTemporarySuspension=$plan.RequiresTemporarySuspension;SigmaEvtxCredit=0}
    }
    if($JournalPath -or $OriginalResultsPath -or -not $PlanPath -or $PlanHash -cnotmatch '^[0-9a-f]{64}$'){throw 'Restore consumes a reviewed plan path, its exact SHA-256 and a new output directory.'}
    $source=Read-WelaTranscriptRecoveryFile $PlanPath
    if($source.Sha256 -cne $PlanHash){throw 'Supplied reviewed plan hash differs.'}
    $plan=ConvertFrom-WelaRecoveryJson $source.Text
    if($plan.Kind -cne 'WelaTranscriptionRecoveryPlan' -or $plan.SchemaVersion -ne 1){throw 'Unsupported transcription recovery plan.'}
    $rebuilt=New-WelaTranscriptRecoveryPlan $plan.Journal.Path $plan.OriginalResults.Path
    if((Get-WelaRecoveryKey $rebuilt) -cne (Get-WelaRecoveryKey $plan)){throw 'Reviewed plan differs from independently rebuilt original evidence and current observations.'}
    Assert-WelaTranscriptRecoveryBindings $plan $plan.ExpectedPolicy $source.Path $source.Sha256
    if($plan.RequiresTemporarySuspension -and -not $AllowTemporarySuspension){throw 'Restoring this destination requires explicit -TranscriptRecoveryAllowTemporarySuspension consent, including for preview.'}
    if($DryRun) {
        if($OutputPath){throw 'DryRun writes no directory; omit OutputPath.'}
        return [pscustomobject]@{Status='WouldRestore';ExitCode=0;DryRun=$true;Steps=$plan.Steps;SigmaEvtxCredit=0}
    }
    Assert-WelaTranscriptRecoveryLocalPath $OutputPath
    $output=New-WelaRecoveryOutput $OutputPath
    $outputObservation=Get-WelaTranscriptDestination $output
    $report=[pscustomobject][ordered]@{Status='Failed';ExitCode=1;OutputPath=$output;PlanSha256=$source.Sha256;Steps=@();Before=$plan.ExpectedPolicy;After=$null;Diagnostic='';SigmaEvtxCredit=0;Scope='Two typed Windows PowerShell machine transcription values only; no transcript, session adoption, central collection or policy persistence proof.'}
    $expected=Copy-WelaTranscriptRecoveryValue $plan.ExpectedPolicy
    try {
        if(-not $Auto -and (Read-Host 'Restore the reviewed transcription values, including any explicitly consented temporary suspension? (y/N)') -cnotin @('y','Y')){$report.Status='Declined';$report.ExitCode=0}
        else {
            Write-WelaTranscriptRecoveryArtifact $outputObservation 'plan.json' $plan
            $sequence=0
            foreach($step in $plan.Steps) {
                $sequence++
                Assert-WelaTranscriptRecoveryBindings $plan $expected $source.Path $source.Sha256
                $receipt=[pscustomobject]@{Sequence=$sequence;Status='Pending';RecordedUtc=[datetime]::UtcNow.ToString('o');PlanSha256=$source.Sha256;Step=$step;Before=(Copy-WelaTranscriptRecoveryValue $expected);After=$null}
                Write-WelaTranscriptRecoveryArtifact $outputObservation ('{0:d3}-pending.json' -f $sequence) $receipt
                Assert-WelaTranscriptRecoveryBindings $plan $expected $source.Path $source.Sha256
                Set-WelaTranscriptRecoveryValue $step.Name $step.Value
                foreach($view in $expected){$view.Machine.($step.Name)=Copy-WelaTranscriptRecoveryValue $step.Value}
                Assert-WelaTranscriptRecoveryBindings $plan $expected $source.Path $source.Sha256
                $receipt.Status='Confirmed';$receipt.After=Copy-WelaTranscriptRecoveryValue $expected
                Write-WelaTranscriptRecoveryArtifact $outputObservation ('{0:d3}-confirmed.json' -f $sequence) $receipt
                $report.Steps += [pscustomobject]@{Sequence=$sequence;Name=$step.Name;Status='Confirmed';Value=$step.Value}
            }
            Assert-WelaTranscriptRecoveryBindings $plan $plan.RecoverTo $source.Path $source.Sha256
            $report.Status='Restored';$report.ExitCode=0
        }
    } catch {$report.Diagnostic=$_.Exception.Message}
    try {
        $report.After=@(Get-WelaTranscriptPolicy (Get-WelaTranscriptCapability).Views)
        if($report.Status -eq 'Restored') {
            if((Get-WelaRecoveryKey $report.After) -cne (Get-WelaRecoveryKey $plan.RecoverTo)){throw 'Final returned policy differs from the recovery target.'}
            Assert-WelaTranscriptRecoveryBindings $plan $plan.RecoverTo $source.Path $source.Sha256
        }
    }catch{$report.Diagnostic+=' Final policy verification failed: '+$_.Exception.Message;$report.Status='Failed';$report.ExitCode=1}
    # A failed result write fails outward; pending/confirmed receipts remain intact.
    Write-WelaTranscriptRecoveryArtifact $outputObservation 'result.json' $report
    return $report
}
