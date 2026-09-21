# Fixed native automatic-transcription evidence; never provisions a destination or changes policy.
function Initialize-WelaTranscriptProbe {
    if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess){throw 'transcript-probe requires native 64-bit Windows.'}
    $bytes=[IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'TranscriptProbeNative.cs'));$hash=Get-WelaArrivalHash $bytes
    if(-not ('Wela.TranscriptProbe.Item' -as [type])){Add-Type -TypeDefinition ([Text.UTF8Encoding]::new($false,$true).GetString($bytes).Replace('__WELA_TRANSCRIPT_SOURCE_SHA256__',$hash)) -ErrorAction Stop}
    if([Wela.TranscriptProbe.Item]::SourceSha256 -cne $hash){throw 'Loaded transcript helper differs from source; start a fresh PowerShell process.'}
    Initialize-WelaWmiProbeNative
}
function Get-WelaTranscriptProbeKey {param($Value) ConvertTo-Json -InputObject $Value -Depth 20 -Compress}
function Get-WelaTranscriptProbeSources {
    $result=[ordered]@{}
    foreach($name in @('WELA.ps1','scripts/TranscriptProbe.ps1','scripts/TranscriptProbeWorker.ps1','scripts/TranscriptProbeNative.cs','scripts/PowerShellTranscription.ps1','scripts/WmiProbe.ps1','scripts/WmiProbeNative.cs','scripts/ChannelRead.ps1','scripts/WefArrival.ps1','modules/AuditProfiles.psm1')){$result[$name]=(Get-FileHash -LiteralPath (Join-Path $script:ScriptRoot $name) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()}
    [pscustomobject]$result
}
function Get-WelaTranscriptProbeObjectKey {
    param($Observation,[switch]$Directory)
    $value=[ordered]@{Path=$Observation.Path;Identity=$Observation.Identity;CreatedUtc=$Observation.CreatedUtc;Attributes=$Observation.Attributes;Descriptor=$Observation.Descriptor}
    if(-not $Directory){$value.Length=$Observation.Length;$value.WrittenUtc=$Observation.WrittenUtc;$value.Links=$Observation.Links}
    Get-WelaTranscriptProbeKey ([pscustomobject]$value)
}
function Assert-WelaTranscriptProbePolicy {
    param([array]$Policy,[string]$Directory)
    Test-WelaTranscriptSharedPolicy $Policy
    if($Policy.Count -ne 2 -or $Policy[0].View -cne 'Registry64' -or $Policy[1].View -cne 'Registry32'){throw 'Both canonical shared policy views are required.'}
    foreach($view in $Policy){
        $machine=$view.Machine
        if(-not $machine.EnableTranscripting.ValueExists -or $machine.EnableTranscripting.Type -cne 'DWord' -or $machine.EnableTranscripting.Value -ne 1 -or -not $machine.OutputDirectory.ValueExists -or $machine.OutputDirectory.Type -cne 'String' -or $machine.OutputDirectory.Value -isnot [string]){throw 'An already enabled machine transcription policy with explicit literal output is required.'}
        $path=Resolve-WelaArrivalPath $machine.OutputDirectory.Value
        if(-not $path.Equals($Directory,[StringComparison]::OrdinalIgnoreCase)){throw 'Selected destination does not match the current machine transcription policy.'}
        foreach($hive in @('Machine','CurrentUser')){
            foreach($name in @('EnableTranscripting','EnableInvocationHeader')){$value=$view.$hive.$name;if($value.ValueExists -and ($value.Type -cne 'DWord' -or $value.Value -notin @(0,1))){throw 'Unknown typed transcription policy value.'}}
            $value=$view.$hive.OutputDirectory;if($value.ValueExists -and ($value.Type -cne 'String' -or $value.Value -isnot [string])){throw 'Unknown transcription destination value type.'}
        }
    }
}
function Get-WelaTranscriptProbeState {
    param([string]$Directory,$Handle)
    if((Get-Service Winmgmt -ErrorAction Stop).Status -ne 'Running'){throw 'Winmgmt must already be running for host observations; no service is started.'}
    $capability=Get-WelaTranscriptCapability;if($capability.Status -cne 'Supported'){throw $capability.Diagnostic}
    $engine=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)) 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $engine=Resolve-WelaArrivalPath $engine
    $policy=@(Get-WelaTranscriptPolicy @('Registry64','Registry32'));Assert-WelaTranscriptProbePolicy $policy $Directory
    [pscustomobject][ordered]@{Host=(Get-WelaChannelReadHost);Engine=$engine;EngineHash=(Get-FileHash -LiteralPath $engine -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant();InstalledVersion=$capability.EngineVersion;Policy=$policy;Directory=$Handle.Snapshot();TimeZone=[TimeZoneInfo]::Local.Id;OffsetMinutes=[DateTimeOffset]::Now.Offset.TotalMinutes;Sources=(Get-WelaTranscriptProbeSources)}
}
function Get-WelaTranscriptProbeStateKey {
    param($State)
    Get-WelaTranscriptProbeKey ([pscustomobject][ordered]@{Host=$State.Host;Engine=$State.Engine;EngineHash=$State.EngineHash;InstalledVersion=$State.InstalledVersion;Policy=$State.Policy;Directory=(Get-WelaTranscriptProbeObjectKey $State.Directory -Directory);TimeZone=$State.TimeZone;OffsetMinutes=$State.OffsetMinutes;Sources=$State.Sources})
}
function Get-WelaTranscriptProbeInventory {
    param([string]$Directory,[string[]]$Dates)
    $folders=@();$files=@()
    foreach($date in $Dates){
        if($date -cnotmatch '^\d{8}$'){throw 'Invalid bounded transcript date scope.'}
        $path=Join-Path $Directory $date
        if(-not [IO.Directory]::Exists($path)){if(Test-Path -LiteralPath $path){throw 'Expected date folder is not a directory.'};$folders+=[pscustomobject]@{Date=$date;Exists=$false;Observation=$null};continue}
        $null=Resolve-WelaArrivalPath $path;$handle=[Wela.TranscriptProbe.Item]::Directory($path)
        try{
            $observation=$handle.Snapshot();$folders+=[pscustomobject]@{Date=$date;Exists=$true;Observation=$observation}
            foreach($entry in [IO.Directory]::EnumerateFileSystemEntries($path)){
                if($files.Count -ge 256){throw 'Current-date inventory reached its 256-entry limit.'}
                $item=Get-Item -LiteralPath $entry -Force -ErrorAction Stop
                if($item -isnot [IO.FileInfo] -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected directory or reparse entry in the current-date scope.'}
                $file=[Wela.TranscriptProbe.Item]::Metadata($entry)
                try{$files+=$file.Snapshot()}finally{$file.Dispose()}
            }
            if((Get-WelaTranscriptProbeObjectKey $handle.Snapshot() -Directory) -cne (Get-WelaTranscriptProbeObjectKey $observation -Directory)){throw 'Date-directory identity or descriptor changed during enumeration.'}
        }finally{$handle.Dispose()}
    }
    [pscustomobject]@{Dates=$Dates;Folders=$folders;Files=@($files|Sort-Object Path)}
}
function Assert-WelaTranscriptProbeInventory {
    param($Before,$After)
    foreach($folder in $Before.Folders|Where-Object Exists){
        $match=@($After.Folders|Where-Object Date -eq $folder.Date)
        if($match.Count -ne 1 -or -not $match[0].Exists -or (Get-WelaTranscriptProbeObjectKey $folder.Observation -Directory) -cne (Get-WelaTranscriptProbeObjectKey $match[0].Observation -Directory)){throw 'An existing date directory changed or disappeared.'}
    }
    foreach($file in $Before.Files){
        $match=@($After.Files|Where-Object Path -eq $file.Path)
        # Existing sessions can append to their transcripts. Their bytes are never read.
        if($match.Count -ne 1 -or $match[0].Identity -cne $file.Identity -or $match[0].CreatedUtc -cne $file.CreatedUtc -or $match[0].Descriptor -cne $file.Descriptor){throw 'An existing transcript was replaced, removed or had its descriptor changed.'}
    }
}
function Start-WelaTranscriptProbeWorker {
    param($State,[string]$Nonce,$ParentToken,$LaunchEvidence)
    $worker=Join-Path $PSScriptRoot 'TranscriptProbeWorker.ps1'
    $arguments=@('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$worker,'-Nonce',$Nonce)
    $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$State.Engine
    $info.Arguments='-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$worker+'" -Nonce '+$Nonce
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $info.StandardOutputEncoding=[Text.UTF8Encoding]::new($false,$true);$info.StandardErrorEncoding=[Text.UTF8Encoding]::new($false,$true)
    $process=[Diagnostics.Process]::new();$process.StartInfo=$info;$started=$false;$launched=[DateTime]::UtcNow
    try{
        if(-not $process.Start()){throw 'Fixed transcript worker did not start.'};$started=$true
        $LaunchEvidence.ProcessId=$process.Id;$LaunchEvidence.LaunchedUtc=$launched.ToString('o')
        $stdout=[Wela.TranscriptProbe.Item]::Drain($process.StandardOutput,65536);$stderr=[Wela.TranscriptProbe.Item]::Drain($process.StandardError,65536)
        if(-not $process.WaitForExit(30000)){throw 'Fixed transcript worker exceeded thirty seconds.'}
        $exited=[DateTime]::UtcNow;$LaunchEvidence.ExitedUtc=$exited.ToString('o');$LaunchEvidence.ExitCode=$process.ExitCode
        if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout,$stderr),3000)){throw 'Worker output pipes did not close within their bound.'}
        $LaunchEvidence.Stdout=$stdout.Result;$LaunchEvidence.Stderr=$stderr.Result
        if($stdout.Result.Exceeded -or $stderr.Result.Exceeded -or $stdout.Result.Error -or $stderr.Result.Error){throw 'Worker output is oversized or incomplete.'}
        if($process.ExitCode -ne 0 -or $stderr.Result.Text){throw ('Fixed native5.1 worker failed; exit '+$process.ExitCode+'. No transcript fallback was attempted.')}
        $lines=@(($stdout.Result.Text -replace "`r`n","`n").TrimEnd("`r","`n") -split "`n")
        $json=@($lines|Where-Object{$_ -clike 'WELA-WORKER-JSON:*'})
        if($lines.Count -ne 3 -or $json.Count -ne 1){throw 'Unexpected worker output framing.'}
        $operation=ConvertFrom-WelaArrivalJson $json[0].Substring('WELA-WORKER-JSON:'.Length)
        if($operation.Nonce -cne $Nonce -or $operation.ProcessId -ne $process.Id -or $operation.Engine -ine $State.Engine -or $operation.Edition -cne 'Desktop' -or $operation.EngineVersion -cnotmatch '^5\.1\.\d+\.\d+$'){throw 'Fixed worker engine/identity response differs.'}
        $actualArgs=@($operation.Arguments|Select-Object -Skip 1)
        if((Get-WelaTranscriptProbeKey $actualArgs) -cne (Get-WelaTranscriptProbeKey $arguments) -or $operation.Arguments[0] -ine $State.Engine -or $operation.HeaderCommandLine -cne ($operation.Arguments -join ' ')){throw 'Worker command arguments differ from the fixed launch.'}
        if(@($lines|Where-Object{$_ -ceq ('WELA-TRANSCRIPT-BEGIN:'+${Nonce}+':'+$process.Id)}).Count -ne 1 -or @($lines|Where-Object{$_ -ceq ('WELA-TRANSCRIPT-END:'+${Nonce}+':'+$process.Id)}).Count -ne 1){throw 'Fixed worker output markers are missing or ambiguous.'}
        if((Get-WelaWmiProbeTokenKey $operation.BeforeToken -AuthorizationOnly) -cne (Get-WelaWmiProbeTokenKey $ParentToken -AuthorizationOnly) -or (Get-WelaWmiProbeTokenKey $operation.BeforeToken) -cne (Get-WelaWmiProbeTokenKey $operation.AfterToken)){throw 'Worker identity/logon/group attributes differ from the parent or changed during output.'}
        if((Get-WelaTranscriptProbeKey $operation.PolicyBefore) -cne (Get-WelaTranscriptProbeKey $State.Policy) -or (Get-WelaTranscriptProbeKey $operation.PolicyAfter) -cne (Get-WelaTranscriptProbeKey $State.Policy)){throw 'Native worker policy differs from the observed policy.'}
        $begin=ConvertTo-WelaArrivalUtc $operation.StartedUtc;$end=ConvertTo-WelaArrivalUtc $operation.CompletedUtc
        if($begin -lt $launched -or $end -lt $begin -or $end -gt $exited -or $operation.StartOffsetMinutes -ne $State.OffsetMinutes -or $operation.EndOffsetMinutes -ne $State.OffsetMinutes -or $operation.Computer -ine $State.Host.Computer -or $operation.HeaderUser -ine $operation.BeforeToken.Name){throw 'Worker time, time-zone or host context differs.'}
        $assembly=Resolve-WelaArrivalPath $operation.Assembly.Path
        $windows=[Environment]::GetFolderPath([Environment+SpecialFolder]::Windows).TrimEnd('\')+'\'
        if(-not $assembly.StartsWith($windows,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($assembly) -ine 'System.Management.Automation.dll' -or $operation.Assembly.FullName -cnotlike 'System.Management.Automation, Version=3.0.0.0,*' -or (Get-FileHash -LiteralPath $assembly -Algorithm SHA256).Hash.ToLowerInvariant() -cne $operation.Assembly.Sha256){throw 'Native worker assembly evidence differs.'}
        $operation|Add-Member NoteProperty LaunchedUtc $launched.ToString('o');$operation|Add-Member NoteProperty ExitedUtc $exited.ToString('o')
        $operation
    }finally{try{if($started -and -not $process.HasExited){$process.Kill();if(-not $process.WaitForExit(3000)){throw 'Fixed worker termination was not confirmed.'}}}finally{$process.Dispose()}}
}
function ConvertFrom-WelaTranscriptProbeBytes {
    param([byte[]]$Bytes)
    $offset=0;$encoding=[Text.UTF8Encoding]::new($false,$true)
    if($Bytes.Length -ge 3 -and $Bytes[0] -eq 239 -and $Bytes[1] -eq 187 -and $Bytes[2] -eq 191){$offset=3}
    elseif($Bytes.Length -ge 2 -and $Bytes[0] -eq 255 -and $Bytes[1] -eq 254){$offset=2;$encoding=[Text.UnicodeEncoding]::new($false,$true,$true)}
    elseif($Bytes.Length -ge 2 -and $Bytes[0] -eq 254 -and $Bytes[1] -eq 255){$offset=2;$encoding=[Text.UnicodeEncoding]::new($true,$true,$true)}
    $text=$encoding.GetString($Bytes,$offset,$Bytes.Length-$offset)
    if($text.Contains([string][char]0)){throw 'Transcript contains embedded NUL characters.'}
    $text -replace "`r`n","`n"
}
function Test-WelaTranscriptProbeText {
    param([string]$Text,$Operation)
    $header=($Operation.Resources.TranscriptPrologue -replace "`r`n","`n").TrimEnd("`r","`n")
    $footer=($Operation.Resources.TranscriptEpilogue -replace "`r`n","`n").TrimEnd("`r","`n")
    if(-not $header -or -not $footer -or $header.Length -gt 8192 -or $footer.Length -gt 8192){throw 'Unknown native transcript resource templates.'}
    $pattern=[regex]::Escape($header);$tail=[regex]::Escape($footer)
    $fields=[ordered]@{'{0:yyyyMMddHHmmss}'='(?<Start>\d{14})';'{1}'='(?<User>[^\n]{1,512})';'{2}'='(?<RunAs>[^\n]{1,512})';'{3}'='(?<Configuration>[^\n]{0,512})';'{4}'='(?<Machine>[^\n]{1,255})';'{5}'='(?<OS>[^\n]{1,512})';'{6}'='(?<Command>[^\n]{1,4096})';'{7}'='(?<Pid>\d{1,10})';'{8}'='(?<Versions>[\s\S]{1,8192}?)'}
    foreach($key in $fields.Keys){$escaped=[regex]::Escape($key);if(-not $pattern.Contains($escaped)){throw 'Unrecognized native transcript prologue schema.'};$pattern=$pattern.Replace($escaped,$fields[$key])}
    $tail=$tail.Replace([regex]::Escape('{0:yyyyMMddHHmmss}'),'(?<End>\d{14})')
    $match=[regex]::Match($Text,'\A'+$pattern+'\n(?<Body>[\s\S]*?)\n'+$tail+'\n*\z',[Text.RegularExpressions.RegexOptions]::CultureInvariant,[TimeSpan]::FromSeconds(1))
    if(-not $match.Success){return $false}
    foreach($template in @($header,$footer)){$prefix=(@($template -split "`n"|Select-Object -First 2) -join "`n");if([regex]::Matches($Text,[regex]::Escape($prefix)).Count -ne 1){return $false}}
    if($match.Groups['User'].Value -ine $Operation.HeaderUser -or $match.Groups['RunAs'].Value -ine $Operation.BeforeToken.Name -or $match.Groups['Configuration'].Value -cne '' -or $match.Groups['Machine'].Value -ine $Operation.Computer -or $match.Groups['OS'].Value -cne $Operation.OsVersion -or $match.Groups['Command'].Value -cne $Operation.HeaderCommandLine -or [long]$match.Groups['Pid'].Value -ne $Operation.ProcessId){return $false}
    $versions=@($match.Groups['Versions'].Value -split "`n")
    if(@($versions|Where-Object{$_ -ceq ('PSVersion: '+$Operation.EngineVersion)}).Count -ne 1 -or @($versions|Where-Object{$_ -ceq 'PSEdition: Desktop'}).Count -ne 1){return $false}
    $body=@($match.Groups['Body'].Value -split "`n");$begin='WELA-TRANSCRIPT-BEGIN:'+$Operation.Nonce+':'+$Operation.ProcessId;$end='WELA-TRANSCRIPT-END:'+$Operation.Nonce+':'+$Operation.ProcessId
    if(@($body|Where-Object{$_ -ceq $begin}).Count -ne 1 -or @($body|Where-Object{$_ -ceq $end}).Count -ne 1 -or [Array]::IndexOf($body,$begin) -ge [Array]::IndexOf($body,$end)){return $false}
    $offset=[TimeSpan]::FromMinutes($Operation.StartOffsetMinutes)
    $first=[DateTimeOffset]::new([DateTime]::ParseExact($match.Groups['Start'].Value,'yyyyMMddHHmmss',[Globalization.CultureInfo]::InvariantCulture),$offset)
    $last=[DateTimeOffset]::new([DateTime]::ParseExact($match.Groups['End'].Value,'yyyyMMddHHmmss',[Globalization.CultureInfo]::InvariantCulture),$offset)
    return $first -ge (ConvertTo-WelaArrivalUtc $Operation.LaunchedUtc).AddSeconds(-1) -and $first -le (ConvertTo-WelaArrivalUtc $Operation.StartedUtc).AddSeconds(1) -and $last -ge (ConvertTo-WelaArrivalUtc $Operation.CompletedUtc).AddSeconds(-1) -and $last -le (ConvertTo-WelaArrivalUtc $Operation.ExitedUtc).AddSeconds(1) -and $last -ge $first
}
function Write-WelaTranscriptProbeArtifact {
    param([string]$Root,[string]$Name,[byte[]]$Bytes)
    if($Bytes.Length -gt 4194304){throw 'Evidence artifact exceeds four MiB.'}
    $stream=[IO.File]::Open((Join-Path $Root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try{$stream.Write($Bytes,0,$Bytes.Length);$stream.Flush($true);$stream.Position=0;$sha=[Security.Cryptography.SHA256]::Create();try{$hash=([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()};if($hash -cne (Get-WelaArrivalHash $Bytes)){throw 'Written evidence bytes differ.'}}finally{$stream.Dispose()}
    [pscustomobject]@{Name=$Name;Bytes=$Bytes.Length;Sha256=$hash}
}
function Invoke-WelaTranscriptProbe {
    param([ValidateSet('Plan','Run')][string]$Action='Plan',[string]$Directory,[string]$OutputPath)
    if(($Action -eq 'Run') -ne (-not [string]::IsNullOrWhiteSpace($OutputPath))){throw 'Run requires a new TranscriptProbeOutputPath; Plan starts no worker or explicit output.'}
    if(-not $Directory){throw 'Select the existing local TranscriptProbeDirectory.'}
    Initialize-WelaTranscriptProbe
    $directoryPath=Resolve-WelaArrivalPath $Directory
    if(-not [IO.Directory]::Exists($directoryPath)){throw 'Selected transcript directory must already exist.'}
    $handle=[Wela.TranscriptProbe.Item]::Directory($directoryPath);$heldFiles=@();$heldFolders=@();$output=$null
    try{
        $state=Get-WelaTranscriptProbeState $directoryPath $handle;$stateKey=Get-WelaTranscriptProbeStateKey $state
        $dates=@(-1,0,1|ForEach-Object{[DateTime]::Today.AddDays($_).ToString('yyyyMMdd',[Globalization.CultureInfo]::InvariantCulture)})
        $before=Get-WelaTranscriptProbeInventory $directoryPath $dates
        if($Action -eq 'Plan'){return [pscustomobject]@{SchemaVersion=1;Kind='WelaAutomaticTranscriptPlan';Action='Plan';ExitCode=0;Status='ReadyToProbe';State=$state;Inventory=$before;Token=[Wela.WmiProbe.Native]::Snapshot();ReadyRuleCredit=0;SigmaEvtxCredit=0;WriterAuthorization='Unverified';Scope='One new native Windows PowerShell5.1 automatic transcript under this local current identity only'}}
        $output=New-WelaArrivalOutput $OutputPath $directoryPath
        $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaAutomaticTranscriptProbe';Action='Run';Status='Unverified';ExitCode=1;RecordedUtc=[DateTime]::UtcNow.ToString('o');Before=$state;After=$null;InventoryBefore=$before;InventoryAfter=$null;ParentBefore=$null;ParentAfter=$null;Worker=$null;WorkerLaunch=[pscustomobject]@{ProcessId=$null;LaunchedUtc=$null;ExitedUtc=$null;ExitCode=$null;Stdout=$null;Stderr=$null};Transcript=$null;Artifacts=@();Diagnostic='';OutputPath=$output;ReadyRuleCredit=0;SigmaEvtxCredit=0;ConfigurationChanges=0;WriterAuthorization='Unverified';PowerShell7Sessions='Not assessed';Collection='Not verified';Scope='One fixed native5.1 completed automatic text transcript; no retention, immutable-storage or EVTX/Sigma claim'}
        try{
            # Prepare metadata and evidence storage before capturing the actual process-token interval.
            foreach($folder in $before.Folders|Where-Object Exists){$held=[Wela.TranscriptProbe.Item]::Directory($folder.Observation.Path);$heldFolders+= $held;if((Get-WelaTranscriptProbeObjectKey $held.Snapshot() -Directory) -cne (Get-WelaTranscriptProbeObjectKey $folder.Observation -Directory)){throw 'Date-directory changed before worker.'}}
            $fresh=Get-WelaTranscriptProbeState $directoryPath $handle;if((Get-WelaTranscriptProbeStateKey $fresh) -cne $stateKey){throw 'Policy, destination, source or host changed before worker.'}
            $inventory=Get-WelaTranscriptProbeInventory $directoryPath $dates
            Assert-WelaTranscriptProbeInventory $before $inventory
            # Newly created unrelated files during preparation become baseline, never candidate evidence.
            $before=$inventory;$report.InventoryBefore=$before
            $token=[Wela.WmiProbe.Native]::Snapshot();$report.ParentBefore=$token
            $operation=Start-WelaTranscriptProbeWorker $state ([guid]::NewGuid().ToString('N')) $token $report.WorkerLaunch;$report.Worker=$operation
            $after=Get-WelaTranscriptProbeInventory $directoryPath $dates;$report.InventoryAfter=$after;Assert-WelaTranscriptProbeInventory $before $after
            foreach($folder in $after.Folders|Where-Object Exists){$held=[Wela.TranscriptProbe.Item]::Directory($folder.Observation.Path);$heldFolders+=$held;if((Get-WelaTranscriptProbeObjectKey $held.Snapshot() -Directory) -cne (Get-WelaTranscriptProbeObjectKey $folder.Observation -Directory)){throw 'Date directory changed after worker.'}}
            $candidates=@($after.Files|Where-Object{$_.Identity -cnotin @($before.Files.Identity)})
            if($candidates.Count -gt 32){throw 'Fresh transcript candidates exceed the 32-file bound.'}
            $matches=@();$total=0
            foreach($candidate in $candidates){
                if([IO.Path]::GetFileName($candidate.Path) -cnotlike 'PowerShell_transcript*.txt'){throw 'Unexpected fresh file in the selected date scope.'}
                if((ConvertTo-WelaArrivalUtc $candidate.CreatedUtc) -lt (ConvertTo-WelaArrivalUtc $operation.LaunchedUtc).AddSeconds(-2) -or (ConvertTo-WelaArrivalUtc $candidate.WrittenUtc) -gt (ConvertTo-WelaArrivalUtc $operation.ExitedUtc).AddSeconds(2)){throw 'Fresh transcript file timestamps are outside the worker interval.'}
                $file=[Wela.TranscriptProbe.Item]::File($candidate.Path);$heldFiles+=$file
                $observation=$file.Snapshot();if((Get-WelaTranscriptProbeObjectKey $observation) -cne (Get-WelaTranscriptProbeObjectKey $candidate)){throw 'Candidate identity or contents changed after enumeration.'}
                $bytes=$file.Read(1048576);$total+=$bytes.Length;if($total -gt 4194304){throw 'Fresh transcript reads exceed four MiB.'}
                $text=ConvertFrom-WelaTranscriptProbeBytes $bytes
                if(Test-WelaTranscriptProbeText $text $operation){$matches+=[pscustomobject]@{Observation=$observation;Bytes=$bytes;Handle=$file}}
            }
            if($matches.Count -ne 1){throw ('Expected one fresh completed automatic transcript; matching files: '+$matches.Count+'. Writer authorization remains unverified.')}
            $report.After=Get-WelaTranscriptProbeState $directoryPath $handle
            if((Get-WelaTranscriptProbeStateKey $report.After) -cne $stateKey){throw 'Policy, destination, source or host changed during the probe.'}
            $final=Get-WelaTranscriptProbeInventory $directoryPath $dates;Assert-WelaTranscriptProbeInventory $after $final
            if((Get-WelaTranscriptProbeKey @($after.Files.Path)) -cne (Get-WelaTranscriptProbeKey @($final.Files.Path))){throw 'Candidate inventory changed before final verification.'}
            if((Get-WelaTranscriptProbeObjectKey $matches[0].Handle.Snapshot()) -cne (Get-WelaTranscriptProbeObjectKey $matches[0].Observation)){throw 'Matching transcript changed before evidence capture.'}
            $report.ParentAfter=[Wela.WmiProbe.Native]::Snapshot()
            if((Get-WelaWmiProbeTokenKey $report.ParentBefore) -cne (Get-WelaWmiProbeTokenKey $report.ParentAfter)){throw 'Parent authorization context changed during the probe.'}
            $report.Artifacts+=Write-WelaTranscriptProbeArtifact $output 'transcript.txt' $matches[0].Bytes
            $report.Transcript=$matches[0].Observation;$report.Status='CompletedAutomaticTranscript';$report.WriterAuthorization='ObservedForThisChild';$report.ExitCode=0
        }catch{$report.Diagnostic=$_.Exception.Message}
        $report.Artifacts+=Write-WelaTranscriptProbeArtifact $output 'worker.json' ([Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $report.Worker -Depth 18)))
        $null=Write-WelaTranscriptProbeArtifact $output 'result.json' ([Text.UTF8Encoding]::new($false).GetBytes(($report|ConvertTo-Json -Depth 22)))
        return $report
    }finally{foreach($file in $heldFiles){$file.Dispose()};foreach($folder in $heldFolders){$folder.Dispose()};$handle.Dispose()}
}
