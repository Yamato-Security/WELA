# Exact selected QueryList, current primary token, local read-only native execution.
function Get-WelaWefQueryKey {
 param($Value)
 (ConvertTo-Json -InputObject $Value -Depth 32 -Compress).Replace('<','\u003c').Replace('>','\u003e').Replace('&','\u0026').Replace("'",'\u0027')
}
function Initialize-WelaWefQueryNative {
 $bytes=[IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'WefQueryNative.cs'))
 if($bytes.Length -gt 131072){throw 'Native query source exceeds its bound.'};$hash=Get-WelaArrivalHash $bytes
 if(-not('Wela.WefQuery.Native' -as [type])){
  $source=[Text.UTF8Encoding]::new($false,$true).GetString($bytes).TrimStart([char]0xfeff)
  if([regex]::Matches($source,'__WELA_WEF_QUERY_SHA256__').Count -ne 1){throw 'Native query source marker is missing or ambiguous.'}
  Add-Type -TypeDefinition $source.Replace('__WELA_WEF_QUERY_SHA256__',$hash) -ErrorAction Stop
 }
 if([Wela.WefQuery.Native]::SourceSha256 -cne $hash){throw 'Loaded query helper differs from current source.'}
}
function Get-WelaWefQuerySources {
 $result=[ordered]@{}
 foreach($name in @('WELA.ps1','scripts/WefQuery.ps1','scripts/WefQueryNative.cs','scripts/WefQueryWorker.ps1','scripts/ChannelRead.ps1','scripts/WefArrival.ps1','scripts/WecUpdate.ps1','scripts/CustomAuditProfiles.ps1','modules/WefSubscriptions.psm1','modules/AuditProfiles.psm1','modules/NativeProviders.psm1','config/native_channel_profile.json')){
  $result[$name]=(Get-FileHash -LiteralPath (Join-Path $script:ScriptRoot $name) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
 }
 [pscustomobject]$result
}
function Get-WelaWefQueryToken {
 Initialize-WelaWefQueryNative
 ConvertTo-WelaWefQueryTokenObservation ([Wela.WefQueryToken.Native]::Snapshot())
}
function ConvertTo-WelaWefQueryTokenObservation {
 param($Token)
 if($Token -isnot [Wela.WefQueryToken.Token]){throw 'Expected the native query token observation.'}
 # Normalize native DTOs at the boundary, using the same strict shape as worker receipts.
 $observed=ConvertFrom-WelaArrivalJson (Get-WelaWefQueryKey $Token)
 $null=Get-WelaWefQueryTokenKey $observed
 $observed
}
function Get-WelaWefQueryTokenKey {
 param($Token)
 Assert-WelaArrivalObject $Token @('Sid','Name','AuthenticationId','AuthenticationType','ImpersonationLevel','TokenSource','Groups','Privileges')
 foreach($name in @('Sid','Name','AuthenticationId','AuthenticationType','ImpersonationLevel','TokenSource')){if($Token.$name -isnot [string]){throw 'Mistyped query token text.'}}
 if($Token.Sid -cnotmatch '^S-1-\d+(-\d+)+$' -or $Token.AuthenticationId -cnotmatch '^0x[0-9a-f]+$' -or -not $Token.Name -or $Token.TokenSource -cnotin @('Process','EquivalentSelfThread') -or $Token.Groups -isnot [array] -or -not $Token.Groups.Count -or $Token.Privileges -isnot [array]){throw 'Incomplete query token observation.'}
 foreach($group in $Token.Groups){Assert-WelaArrivalObject $group @('Sid','Attributes');if($group.Sid -isnot [string] -or $group.Sid -cnotmatch '^S-1-\d+(-\d+)+$'){throw 'Invalid group SID.'};Assert-WelaWefQueryUInt $group.Attributes}
 foreach($privilege in $Token.Privileges){Assert-WelaArrivalObject $privilege @('Luid','Attributes');if($privilege.Luid -isnot [string] -or $privilege.Luid -cnotmatch '^0x[0-9a-f]+$'){throw 'Invalid token privilege.'};Assert-WelaWefQueryUInt $privilege.Attributes}
 Get-WelaWefQueryKey ([pscustomobject][ordered]@{Sid=$Token.Sid;Name=$Token.Name;AuthenticationId=$Token.AuthenticationId;AuthenticationType=$Token.AuthenticationType;Groups=$Token.Groups;Privileges=$Token.Privileges})
}
function Assert-WelaWefQueryUInt {param($Value) if(($Value -isnot [int] -and $Value -isnot [long] -and $Value -isnot [uint32]) -or $Value -lt 0 -or $Value -gt [uint32]::MaxValue){throw 'Expected a native unsigned integer.'}}
function Assert-WelaWefQuerySourceConfig {
 param($Config)
 Assert-WelaArrivalObject $Config @('SchemaVersion','Role','CollectorFqdn','CollectorUri','Authentication','SourceSids','SubscriptionFiles','Hardening','SubscriptionManagerSlot','RefreshSeconds','GrantNetworkServiceRead','ApplyChannelProfile','GrantCapi2Read')
 foreach($name in @('SchemaVersion','SubscriptionManagerSlot','RefreshSeconds')){if($Config.$name -isnot [int] -and $Config.$name -isnot [long]){throw 'Source config requires integer schema/slot/refresh fields.'}}
 foreach($name in @('Role','CollectorFqdn','CollectorUri','Authentication','Hardening')){if($Config.$name -isnot [string]){throw 'Source config requires typed text fields.'}}
 foreach($name in @('SourceSids','SubscriptionFiles')){if($Config.$name -isnot [array]){throw 'Source config requires explicit SID/file arrays.'};foreach($value in $Config.$name){if($value -isnot [string] -or -not $value){throw 'Source config requires nonempty SID/file strings.'}}}
 foreach($name in @('GrantNetworkServiceRead','ApplyChannelProfile','GrantCapi2Read')){if($Config.$name -isnot [bool]){throw 'Source config requires explicit Boolean permission settings.'}}
}
function Import-WelaWefQuerySelection {
 param([string]$ConfigPath,[string]$SubscriptionId)
 if(-not $ConfigPath -or -not $SubscriptionId -or $SubscriptionId.Length -gt 256 -or $SubscriptionId -match '[\x00-\x1f]'){throw 'An exact source config path and subscription ID are required.'}
 $capture=@{Files=[Collections.Generic.List[object]]::new();Bytes=0;Texts=[Collections.Generic.List[string]]::new()}
 # This synchronous callback retains the caller's script scope. GetNewClosure
 # creates a dynamic module that cannot see script-local artifact helpers.
 $reader={param($path)
  $file=Read-WelaWecUpdateFile $path 1048576
  if($capture.Files.Path -contains $file.Path){throw 'Duplicate input file path.'}
  if($capture.Files.Count -eq 0){$json=ConvertFrom-WelaArrivalJson $file.Text;Assert-WelaWefQuerySourceConfig $json}
  $capture.Bytes+=[Text.Encoding]::UTF8.GetByteCount($file.Text);if($capture.Bytes -gt 4194304){throw 'WEF input text exceeds four MiB aggregate.'}
  $capture.Files.Add([pscustomobject]@{Path=$file.Path;Sha256=$file.Hash});$capture.Texts.Add($file.Text)
  $file.Text
 }
 $model=Import-WelaWefConfig -Path $ConfigPath -Role Source -ReadText $reader
 $selected=@($model.Subscriptions|Where-Object Id -CEQ $SubscriptionId)
 if($selected.Count -ne 1){throw 'Select one exact subscription ID from the source config.'};$selected=$selected[0]
 $doc=Read-WelaWefXml $selected.Xml;$query=[string]$doc.DocumentElement.SelectSingleNode('*[local-name()="Query"]').InnerText
 $parsed=ConvertFrom-WelaWefQuery $query
 if($query.Length -gt 65536 -or $parsed.Channels.Count -gt 16 -or $parsed.Filters.Count -gt 128){throw 'Selected QueryList exceeds 65536 characters, 16 channels or 128 filters.'}
 $index=0;while($model.Subscriptions[$index].Id -cne $SubscriptionId){$index++}
 [pscustomobject][ordered]@{Id=$SubscriptionId;RequestedEnabled=$selected.Definition.Enabled;CollectorFqdn=$model.Config.CollectorFqdn;CollectorUri=$model.Config.CollectorUri;Query=$query;QuerySha256=(Get-WelaArrivalHash ([Text.UTF8Encoding]::new($false).GetBytes($query)));Channels=@($parsed.Channels);Filters=@($parsed.Filters);Files=@($capture.Files.ToArray());ConfigText=$capture.Texts[0];SubscriptionText=$capture.Texts[$index+1]}
}
function Get-WelaWefQueryHost {
 if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess){throw 'Native 64-bit Windows is required.'}
 foreach($service in @('Winmgmt','EventLog')){if((Get-Service -Name $service -ErrorAction Stop).Status -ne 'Running'){throw 'Observation services must already be running.'}}
 $observed=Get-WelaChannelReadHost;$dns=[Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
 $observed|Add-Member NoteProperty DnsHostName ([string]$dns.HostName)
 $observed|Add-Member NoteProperty DnsSuffix ([string]$dns.DomainName)
 $observed
}
function Get-WelaWefQueryChannelState {
 param([string[]]$Channels)
 foreach($channel in $Channels){Get-WelaNativeChannel -Name $channel}
}
function Assert-WelaWefQueryInputs {
 param($Selection)
 foreach($file in $Selection.Files){if((Read-WelaWecUpdateFile $file.Path 1048576).Hash -cne $file.Sha256){throw 'Original WEF configuration or subscription bytes changed.'}}
}
function Get-WelaWefQueryEngine {
 $path=(Get-Process -Id $PID -ErrorAction Stop).Path
 if([IO.Path]::GetFileName($path) -notin @('powershell.exe','pwsh.exe') -or $PSVersionTable.PSVersion.Major -notin @(5,7)){throw 'Native Windows PowerShell 5.1 or PowerShell 7 is required.'}
 [pscustomobject]@{Path=$path;Sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();Version=$PSVersionTable.PSVersion.ToString();ModulePath=[IO.Path]::Combine($PSHOME,'Modules')}
}
function Close-WelaWefQueryWorker {
 param($Process,$Result)
 if($Result.Started){
  $exited=$false;try{$exited=$Process.HasExited}catch{$Result.Diagnostic+=' Exit observation failed: '+$_.Exception.Message}
  if(-not $exited){try{$Process.Kill()}catch{$Result.Diagnostic+=' Termination request failed: '+$_.Exception.Message};try{$exited=$Process.WaitForExit(5000)}catch{$Result.Diagnostic+=' Termination wait failed: '+$_.Exception.Message}}
  $Result.TerminationConfirmed=[bool]$exited;if(-not $exited){$Result.Diagnostic+=' Worker termination unconfirmed.'}
 }
 try{$Process.Dispose()}catch{$Result.Diagnostic+=' Process cleanup failed: '+$_.Exception.Message}
}
function Start-WelaWefQueryWorker {
 param($Engine,[string]$RequestPath,[string]$RequestHash)
 $worker=Join-Path $PSScriptRoot 'WefQueryWorker.ps1'
 foreach($path in @($Engine.Path,$worker,$RequestPath)){if($path.Contains('"') -or $path.EndsWith('\') -or $path -match '[\x00-\x1f]'){throw 'Ambiguous query worker path.'}}
 Initialize-WelaWefQueryNative
 $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$Engine.Path;$info.Arguments='-NoLogo -NoProfile -NonInteractive -File "'+$worker+'" -RequestPath "'+$RequestPath+'" -RequestHash '+$RequestHash
 $info.EnvironmentVariables['PSModulePath']=$Engine.ModulePath;$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true;$info.StandardOutputEncoding=[Text.UTF8Encoding]::new($false);$info.StandardErrorEncoding=[Text.UTF8Encoding]::new($false)
 $result=[pscustomobject]@{Started=$false;ProcessId=$null;ExitCode=$null;TimedOut=$false;TerminationConfirmed=$false;Receipt=$null;Diagnostic=''};$process=[Diagnostics.Process]::new();$process.StartInfo=$info
 try{
  if(-not $process.Start()){throw 'Query worker did not start.'};$result.Started=$true;$result.ProcessId=$process.Id
  $stdout=[Wela.WefQuery.Native]::ReadPipe($process.StandardOutput,33554432);$stderr=[Wela.WefQuery.Native]::ReadPipe($process.StandardError,65536)
  if(-not $process.WaitForExit(45000)){$result.TimedOut=$true;throw 'Native query worker exceeded 45 seconds.'};$result.ExitCode=$process.ExitCode
  if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout,$stderr),5000)){throw 'Native query output drain timed out.'}
  if($stderr.Result){throw ('Query worker error output: '+$stderr.Result)}
  $result.Receipt=ConvertFrom-WelaArrivalJson $stdout.Result
 }catch{$result.Diagnostic=$_.Exception.Message}finally{Close-WelaWefQueryWorker $process $result}
 $result
}
function Assert-WelaWefQueryNativeResult {
 param($Result,[string[]]$Channels,[int]$MaximumEvents)
 Assert-WelaArrivalObject $Result @('Opened','Complete','Capped','CleanupConfirmed','NativeError','Diagnostic','Channels','DiagnosticChannels','DiagnosticNativeError','Events')
 foreach($name in @('Opened','Complete','Capped','CleanupConfirmed')){if($Result.$name -isnot [bool]){throw 'Mistyped native query outcome.'}}
 if($Result.Diagnostic -isnot [string] -or $Result.Events -isnot [array] -or $Result.Events.Count -gt $MaximumEvents){throw 'Invalid native query evidence count or diagnostic.'}
 foreach($name in @('NativeError','DiagnosticNativeError')){if($null -ne $Result.$name){Assert-WelaWefQueryUInt $Result.$name}}
 foreach($field in @('Channels','DiagnosticChannels')){
  $entries=$Result.$field;if($entries -isnot [array] -or $entries.Count -gt 128){throw 'Invalid native query status list.'}
  foreach($entry in $entries){Assert-WelaArrivalObject $entry @('Channel','Error');if($entry.Channel -isnot [string] -or $entry.Channel -cnotin $Channels){throw 'Native query status refers to an unselected channel.'};Assert-WelaWefQueryUInt $entry.Error}
 }
 if(-not $Result.Opened -and ($Result.Events.Count -or $Result.Channels.Count -or $Result.Complete -or $Result.Capped -or $null -eq $Result.NativeError)){throw 'An unopened strict query cannot have matching evidence.'}
 if($Result.Opened -and ($Result.DiagnosticChannels.Count -or $null -ne $Result.DiagnosticNativeError)){throw 'Successful strict query has unexpected alternate diagnostic evidence.'}
 if($Result.Complete -and ($Result.Capped -or -not $Result.CleanupConfirmed -or $null -ne $Result.NativeError -or $Result.Diagnostic)){throw 'Native completeness contradicts an error/cap/cleanup outcome.'}
 if($Result.Opened){foreach($channel in $Channels){if(-not @($Result.Channels|Where-Object Channel -CEQ $channel).Count){throw 'Native query status omits a selected channel.'}}}
 $bytes=0
 foreach($xml in $Result.Events){if($xml -isnot [string] -or $xml.Length -gt 524287){throw 'Invalid or oversized event XML.'};$bytes+=[Text.Encoding]::UTF8.GetByteCount($xml);if($bytes -gt 4194304){throw 'Matching event XML exceeds four MiB.'}}
}
function Read-WelaWefQueryEvent {
 param([string]$Xml,[string[]]$Channels,$HostContext)
 $doc=Read-WelaWefXml $Xml;$root=$doc.DocumentElement
 if($root.LocalName -cne 'Event' -or $root.NamespaceURI -cne 'http://schemas.microsoft.com/win/2004/08/events/event'){throw 'Native result is not Windows Event XML.'}
 $ns=[Xml.XmlNamespaceManager]::new($doc.NameTable);$ns.AddNamespace('e',$root.NamespaceURI)
 $system=@($root.SelectNodes('e:System',$ns));if($system.Count -ne 1){throw 'Event System identity is missing or ambiguous.'}
 foreach($name in @('Provider','EventID','EventRecordID','Channel','Computer','TimeCreated')){if(@($system[0].SelectNodes('e:'+$name,$ns)).Count -ne 1){throw 'Event identity is missing or duplicated.'}}
 $channel=[string]$system[0].SelectSingleNode('e:Channel',$ns).InnerText;$machine=[string]$system[0].SelectSingleNode('e:Computer',$ns).InnerText;$record=[string]$system[0].SelectSingleNode('e:EventRecordID',$ns).InnerText;$provider=$system[0].SelectSingleNode('e:Provider',$ns).GetAttribute('Name');$eventId=[string]$system[0].SelectSingleNode('e:EventID',$ns).InnerText
 $names=@([string]$HostContext.Computer);if($HostContext.DnsHostName){$names+=[string]$HostContext.DnsHostName;if($HostContext.DnsSuffix){$names+=([string]$HostContext.DnsHostName+'.'+[string]$HostContext.DnsSuffix)}}
 if($channel -cnotin $Channels -or -not $machine -or $machine -inotIn $names -or $record -cnotmatch '^[1-9][0-9]{0,18}$' -or -not $provider -or $eventId -cnotmatch '^[0-9]{1,5}$'){throw 'Returned event identity differs from selected local provenance.'}
 $time=ConvertTo-WelaArrivalUtc $system[0].SelectSingleNode('e:TimeCreated',$ns).GetAttribute('SystemTime')
 [pscustomobject]@{Channel=$channel;Computer=$machine;RecordId=[long]$record;Provider=$provider;EventId=[int]$eventId;TimeCreatedUtc=$time.ToString('o')}
}
function Invoke-WelaWefQuery {
 param([string]$ConfigPath,[string]$SubscriptionId,[string]$OutputPath,[ValidateRange(1,64)][int]$MaximumEvents=16)
 $selection=Import-WelaWefQuerySelection $ConfigPath $SubscriptionId
 $hostState=Get-WelaWefQueryHost;$sources=Get-WelaWefQuerySources;$engine=Get-WelaWefQueryEngine
 if(-not $OutputPath){throw 'wef-query requires a new output directory.'};$output=New-WelaArrivalOutput $OutputPath $script:ScriptRoot
 $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaWefQueryPreflight';Status='Unverified';ExitCode=1;SubscriptionId=$selection.Id;RequestedEnabled=$selection.RequestedEnabled;CollectorFqdn=$selection.CollectorFqdn;CollectorUri=$selection.CollectorUri;QuerySha256=$selection.QuerySha256;MaximumEvents=$MaximumEvents;Sources=$sources;Inputs=$selection.Files;Host=$hostState;Engine=$engine;ReaderBefore=$null;ReaderAfter=$null;ChannelBefore=@();ChannelAfter=@();Worker=$null;Query=$null;Matches=@();Artifacts=@();Diagnostic='';ConfigurationChanges=0;ReadyRuleCredit=0;Forwarding='Not tested';SourceServiceTokenAccess='Not tested; actual caller token only';Scope='Exact selected local QueryList at observation time; disabled selection may read historical events.'}
 try{
  $report.Artifacts+=Write-WelaWecUpdateArtifact $output 'source-config.json' $selection.ConfigText
  $report.Artifacts+=Write-WelaWecUpdateArtifact $output 'subscription.xml' $selection.SubscriptionText
  $report.Artifacts+=Write-WelaWecUpdateArtifact $output 'query.xml' $selection.Query
  $report.ChannelBefore=@(Get-WelaWefQueryChannelState $selection.Channels)
  $report.ReaderBefore=Get-WelaWefQueryToken;$tokenKey=Get-WelaWefQueryTokenKey $report.ReaderBefore
  $request=[pscustomobject]@{SchemaVersion=1;Kind='WelaWefQueryRequest';Nonce=[guid]::NewGuid().ToString('N');Query=$selection.Query;QuerySha256=$selection.QuerySha256;Channels=$selection.Channels;MaximumEvents=$MaximumEvents;Sources=$sources;Host=$hostState;Reader=$report.ReaderBefore;Engine=$engine}
  $artifact=Write-WelaWecUpdateArtifact $output 'request.json' (Get-WelaWefQueryKey $request);$report.Artifacts+=$artifact
  Assert-WelaWefQueryInputs $selection
  if((Get-WelaWefQueryKey (Get-WelaWefQuerySources)) -cne (Get-WelaWefQueryKey $sources) -or (Get-WelaWefQueryTokenKey (Get-WelaWefQueryToken)) -cne $tokenKey){throw 'Sources or actual reader changed before query.'}
  $worker=Start-WelaWefQueryWorker $engine (Join-Path $output 'request.json') $artifact.Sha256;$report.Worker=$worker
  if(-not $worker.Started -or -not $worker.TerminationConfirmed -or $worker.TimedOut -or $worker.Diagnostic -or $worker.ExitCode -ne 0 -or -not $worker.Receipt){throw ('Query worker did not complete verified observation. '+$worker.Diagnostic)}
  $receipt=$worker.Receipt;Assert-WelaArrivalObject $receipt @('SchemaVersion','Kind','Nonce','ProcessId','Engine','ModulePath','StartedUtc','CompletedUtc','ReaderBefore','ReaderAfter','Host','Sources','QuerySha256','Result')
  foreach($name in @('Kind','Nonce','ModulePath','QuerySha256')){if($receipt.$name -isnot [string]){throw 'Mistyped worker receipt identity.'}}
  if(($receipt.SchemaVersion -isnot [int] -and $receipt.SchemaVersion -isnot [long]) -or $receipt.SchemaVersion -ne 1 -or $receipt.Kind -cne 'WelaWefQueryWorker' -or $receipt.Nonce -cne $request.Nonce -or ($receipt.ProcessId -isnot [int] -and $receipt.ProcessId -isnot [long]) -or $receipt.ProcessId -ne $worker.ProcessId -or $receipt.ModulePath -cne $engine.ModulePath -or $receipt.QuerySha256 -cne $selection.QuerySha256 -or (Get-WelaWefQueryKey $receipt.Engine) -cne (Get-WelaWefQueryKey $engine) -or (Get-WelaWefQueryKey $receipt.Host) -cne (Get-WelaWefQueryKey $hostState) -or (Get-WelaWefQueryKey $receipt.Sources) -cne (Get-WelaWefQueryKey $sources)){throw 'Worker receipt differs from actual reviewed query/engine/host/source context.'}
  if((Get-WelaWefQueryTokenKey $receipt.ReaderBefore) -cne $tokenKey -or (Get-WelaWefQueryTokenKey $receipt.ReaderAfter) -cne $tokenKey){throw 'Worker token differs from the actual caller or changed during query.'}
  if((ConvertTo-WelaArrivalUtc $receipt.StartedUtc) -gt (ConvertTo-WelaArrivalUtc $receipt.CompletedUtc)){throw 'Worker time interval is invalid.'}
  Assert-WelaWefQueryNativeResult $receipt.Result $selection.Channels $MaximumEvents
  $report.Artifacts+=Write-WelaWecUpdateArtifact $output 'worker.json' (Get-WelaWefQueryKey $receipt)
  $report.Query=$receipt.Result;$number=0;$seen=@{}
  foreach($xml in $receipt.Result.Events){$metadata=Read-WelaWefQueryEvent $xml $selection.Channels $hostState;$key=$metadata.Channel+':'+$metadata.RecordId;if($seen[$key]){throw 'Duplicate native event identity.'};$seen[$key]=$true;$number++;$name='event-{0:d3}.xml' -f $number;$report.Artifacts+=Write-WelaWecUpdateArtifact $output $name $xml;$report.Matches+=[pscustomobject]@{Artifact=$name;Metadata=$metadata}}
  # XML is retained in named artifacts/worker evidence, not repeated in the manifest.
  $report.Query.Events=@();$worker.Receipt=$null
  $report.ChannelAfter=@(Get-WelaWefQueryChannelState $selection.Channels);$report.ReaderAfter=Get-WelaWefQueryToken
  Assert-WelaWefQueryInputs $selection
  if((Get-WelaWefQueryKey (Get-WelaWefQueryHost)) -cne (Get-WelaWefQueryKey $hostState) -or (Get-WelaWefQueryKey (Get-WelaWefQuerySources)) -cne (Get-WelaWefQueryKey $sources) -or (Get-WelaWefQueryTokenKey $report.ReaderAfter) -cne $tokenKey -or (Get-WelaWefQueryKey (Get-WelaWefQueryEngine)) -cne (Get-WelaWefQueryKey $engine) -or (Get-WelaWefQueryKey $report.ChannelAfter) -cne (Get-WelaWefQueryKey $report.ChannelBefore)){throw 'Host/token/source/engine or channel configuration changed during query.'}
  foreach($file in $report.Artifacts){if((Get-FileHash -LiteralPath (Join-Path $output $file.Name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $file.Sha256){throw 'Retained query evidence changed.'}}
  $result=$report.Query
  if($result.Opened -and $result.Complete -and $result.CleanupConfirmed -and -not $result.Capped -and $null -eq $result.NativeError -and -not $result.Diagnostic -and -not @($result.Channels|Where-Object Error -NE 0).Count){$report.Status=if($report.Matches.Count){'MatchesObserved'}else{'ReadAllowedEmpty'};$report.ExitCode=0}
  elseif($result.Opened){$report.Status='Partial'}else{$report.Status='QueryFailed'}
 }catch{$report.Diagnostic=$_.Exception.Message}
 $null=Write-WelaWecUpdateArtifact $output 'manifest.json' (Get-WelaWefQueryKey $report)
 $report
}
