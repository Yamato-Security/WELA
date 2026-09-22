# Fixture-only owned account and temporary CAPI2 deny ACE. Product is read-only.
param([switch]$AllowDisposableAccount)
$ErrorActionPreference='Stop'
if(-not $AllowDisposableAccount -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or [Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess){throw 'Explicit disposable GitHub-hosted Windows fixture required.'}
$repo=Split-Path $PSScriptRoot -Parent;$script:ScriptRoot=$repo
Import-Module (Join-Path $repo 'modules/AuditProfiles.psm1') -ErrorAction Stop
Import-Module (Join-Path $repo 'modules/WefSubscriptions.psm1') -ErrorAction Stop
foreach($name in @('Configuration','WefArrival','WecUpdate','ChannelRead','WefQuery')){. (Join-Path $repo ('scripts/'+$name+'.ps1'))}
$hostState=Get-WelaWefQueryHost
if($hostState.DomainJoined -or $hostState.DomainRole -ne 2 -or $hostState.ProductType -ne 3){throw 'Standalone disposable Server fixture required.'}
$nonce=[guid]::NewGuid().ToString('N');$root=New-WelaArrivalOutput (Join-Path $env:RUNNER_TEMP ('wela-wef-query-'+$nonce)) $repo
$code=Join-Path $root 'code';$null=New-Item -ItemType Directory $code
foreach($name in @('WELA.ps1','scripts','modules','config')){Copy-Item -LiteralPath (Join-Path $repo $name) -Destination $code -Recurse}
$engine=(Get-Process -Id $PID).Path;$channel='Microsoft-Windows-CAPI2/Operational';$userName='WelaQ'+$nonce.Substring(0,12);$ownedSid=$null;$aclChanged=$false;$passed=$false;$cleanupErrors=@();$script:assertions=0
function Key($value){Get-WelaWefQueryKey $value}
function Assert($value,[string]$message){if(-not $value){throw $message};$script:assertions++}
function Save([string]$name,$value){[IO.File]::WriteAllText((Join-Path $root $name),(Key $value),[Text.UTF8Encoding]::new($false))}
function Services {@(Get-CimInstance Win32_Service -Filter "Name='WinRM' OR Name='Wecsvc' OR Name='Winmgmt' OR Name='EventLog'"|Sort-Object Name|Select-Object Name,State,StartMode)}
function NativeChannels {@('System','Security',$channel)|ForEach-Object {Get-WelaNativeChannel $_}}
function New-Case([string]$name,[string]$query){
 $inputDirectory=Join-Path $root ('input-'+$name);$null=New-Item -ItemType Directory $inputDirectory
 $config=Get-Content -LiteralPath (Join-Path $repo 'config/wef-examples/source.json') -Raw|ConvertFrom-Json;$config.SubscriptionFiles=@('subscription.xml')
 $xml=Read-WelaWefXml ([IO.File]::ReadAllText((Join-Path $repo 'config/wef-examples/native-security.xml')))
 $xml.DocumentElement.SelectSingleNode('*[local-name()="SubscriptionId"]').InnerText='Wela Query '+$nonce
 $xml.DocumentElement.SelectSingleNode('*[local-name()="Enabled"]').InnerText='false'
 $xml.DocumentElement.SelectSingleNode('*[local-name()="Description"]').InnerText='Native read-only query 日本語 Ω '+$nonce
 $xml.DocumentElement.SelectSingleNode('*[local-name()="Query"]').InnerText=$query
 [IO.File]::WriteAllText((Join-Path $inputDirectory 'source.json'),(Key $config),[Text.UTF8Encoding]::new($false))
 [IO.File]::WriteAllText((Join-Path $inputDirectory 'subscription.xml'),$xml.OuterXml,[Text.UTF8Encoding]::new($false))
 [pscustomobject]@{Name=$name;Config=(Join-Path $inputDirectory 'source.json');Id=('Wela Query '+$nonce)}
}
function Invoke-Public($case,[int]$expected,[int]$maximum=16,[switch]$AsUser){
 $parent=if($AsUser){$readerHome}else{$root};$output=Join-Path $parent ('result-'+$case.Name)
 $all=@('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $code 'WELA.ps1'),'wef-query','-WefQueryConfigPath',$case.Config,'-WefQuerySubscriptionId',$case.Id,'-WefQueryOutputPath',$output,'-WefQueryMaximumEvents',[string]$maximum)
 foreach($arg in $all){if($arg.Contains('"') -or $arg.EndsWith('\') -or $arg -match '[\x00-\x1f]'){throw 'Ambiguous fixture argument.'}}
 $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$engine;$start.Arguments=(@($all|ForEach-Object {'"'+$_+'"'}) -join ' ');$start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
 if($AsUser){$start.UserName=$userName;$start.Domain=[Environment]::MachineName;$start.Password=$password;$start.LoadUserProfile=$true;$start.WorkingDirectory=$readerHome;$start.EnvironmentVariables['TEMP']=$readerHome;$start.EnvironmentVariables['TMP']=$readerHome}
 $process=[Diagnostics.Process]::new();$process.StartInfo=$start;$state=[pscustomobject]@{Started=$false;TerminationConfirmed=$false;Diagnostic=''}
 try{
  if(-not $process.Start()){throw 'Public query command did not start.'};$state.Started=$true
  $stdout=[Wela.WefQuery.Native]::ReadPipe($process.StandardOutput,50331648);$stderr=[Wela.WefQuery.Native]::ReadPipe($process.StandardError,1048576)
  if(-not $process.WaitForExit(180000)){throw 'Public query exceeded three minutes.'}
  if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout,$stderr),5000)){throw 'Public output drain timed out.'}
  Save ($case.Name+'-stdout.json') $stdout.Result;Save ($case.Name+'-stderr.json') $stderr.Result
  Assert ($process.ExitCode -eq $expected) ("Public $($case.Name) exit $($process.ExitCode), expected $expected. "+$stderr.Result+' '+$stdout.Result)
 }finally{Close-WelaWefQueryWorker $process $state;if($state.Diagnostic -or -not $state.TerminationConfirmed){$script:cleanupErrors+='Public child cleanup: '+$state.Diagnostic}}
 $manifest=ConvertFrom-WelaArrivalJson ([IO.File]::ReadAllText((Join-Path $output 'manifest.json')))
 Assert ($manifest.ConfigurationChanges -eq 0 -and $manifest.ReadyRuleCredit -eq 0 -and $manifest.RequestedEnabled -eq $false) 'Read-only/disabled selection boundary.'
 Assert ($manifest.Worker.TerminationConfirmed -and -not $manifest.Worker.Diagnostic) 'Actual bounded worker completed.'
 foreach($artifact in $manifest.Artifacts){$path=Join-Path $output $artifact.Name;Assert ((Get-Item -LiteralPath $path).Length -eq $artifact.Bytes -and (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $artifact.Sha256) 'Actual artifact bytes/hash.'}
 foreach($file in $manifest.Inputs){Assert ((Get-FileHash -LiteralPath $file.Path -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $file.Sha256) 'Original retained native input bytes.'}
 if($AsUser){Assert ($manifest.ReaderBefore.Sid -ceq $ownedSid -and $manifest.ReaderBefore.Groups.Sid -notcontains 'S-1-5-32-544' -and $manifest.ReaderBefore.Groups.Sid -notcontains 'S-1-5-32-573') 'Actual owned standard-user token.'}
 $manifest
}
$before=[pscustomobject]@{Host=$hostState;Services=(Services);Channels=(NativeChannels);Masks=(Get-WelaEffectiveAuditPolicy);Precedence=(Get-WelaRegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' SCENoApplyLegacyAuditPolicy);Token=(Get-WelaWefQueryToken)}
Save 'original.json' $before
try{
 $record=Get-WinEvent -LogName System -MaxEvents 1 -ErrorAction Stop
 try{$recordId=$record.RecordId;$originalXml=$record.ToXml()}finally{$record.Dispose()}
 [IO.File]::WriteAllText((Join-Path $root 'original-event.xml'),$originalXml,[Text.UTF8Encoding]::new($false))
 $query='<QueryList><Query Id="0" Path="System"><Select Path="System">*[System[EventRecordID='+$recordId+']]</Select></Query></QueryList>'
 $match=Invoke-Public (New-Case 'match' $query) 0
 Assert ($match.Status -ceq 'MatchesObserved' -and $match.Matches.Count -eq 1 -and $match.Matches[0].Metadata.RecordId -eq $recordId) 'Actual exact System record selected.'
 $found=[IO.File]::ReadAllText((Join-Path $root 'result-match/event-001.xml'))
 Assert ((Get-WelaWefXmlKey (Read-WelaWefXml $found).DocumentElement) -ceq (Get-WelaWefXmlKey (Read-WelaWefXml $originalXml).DocumentElement)) 'Actual returned full event matches independent native XML.'
 $suppressed=$query.Replace('</Query>','<Suppress Path="System">*[System[EventRecordID='+$recordId+']]</Suppress></Query>')
 $empty=Invoke-Public (New-Case 'suppress' $suppressed) 0
 Assert ($empty.Status -ceq 'ReadAllowedEmpty' -and $empty.Matches.Count -eq 0 -and $empty.Query.Complete) 'Actual Suppress excludes the selected event and ends empty.'
 $invalid=Invoke-Public (New-Case 'invalid' '<QueryList><Query Id="0" Path="System"><Select>*[System[EventID=]]</Select></Query></QueryList>') 1
 Assert ($invalid.Status -ceq 'QueryFailed' -and -not $invalid.Query.Opened -and $invalid.Query.NativeError -ne 0 -and $invalid.Matches.Count -eq 0) 'Native invalid XPath cannot become successful evidence.'
 $missing='Microsoft-Windows-WelaMissing-'+$nonce+'/Operational'
 $mixedQuery=$query.Replace('</QueryList>','<Query Id="1" Path="'+$missing+'"><Select>*</Select></Query></QueryList>')
 $mixed=Invoke-Public (New-Case 'missing' $mixedQuery) 1
 Assert ($mixed.Status -ceq 'QueryFailed' -and -not $mixed.Query.Opened -and $mixed.Matches.Count -eq 0) 'A missing selected channel fails the strict mixed query.'
 Assert (@($mixed.Query.DiagnosticChannels|Where-Object {$_.Channel -ceq $missing -and $_.Error -ne 0}).Count -eq 1) 'Separate native diagnostics preserve missing-channel failure.'
 $capped=Invoke-Public (New-Case 'capped' '<QueryList><Query Id="0" Path="System"><Select>*</Select></Query></QueryList>') 1 1
 Assert ($capped.Status -ceq 'Partial' -and $capped.Query.Capped -and -not $capped.Query.Complete -and $capped.Matches.Count -eq 1) 'Actual second native record proves event cap.'
 Assert ((Key (Services)) -ceq (Key $before.Services) -and (Key (NativeChannels)) -ceq (Key $before.Channels)) 'Admin public cases preserve services and all selected channel settings.'
 $password=ConvertTo-SecureString ('Wela!9'+[guid]::NewGuid().ToString('N')+'rA#') -AsPlainText -Force
 $user=New-LocalUser -Name $userName -Password $password -Description ('WELA query '+$nonce) -AccountNeverExpires;$ownedSid=$user.SID.Value
 Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $user
 $readerHome=Join-Path $root 'reader';$null=New-Item -ItemType Directory $readerHome
 $acl=Get-Acl -LiteralPath $root;$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($user.SID,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'));Set-Acl -LiteralPath $root -AclObject $acl
 $acl=Get-Acl -LiteralPath $readerHome;$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($user.SID,'FullControl','ContainerInherit,ObjectInherit','None','Allow'));Set-Acl -LiteralPath $readerHome -AclObject $acl
 $channelBefore=@($before.Channels|Where-Object Name -CEQ $channel)[0];$descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($channelBefore.SecurityDescriptor)
 $descriptor.DiscretionaryAcl.InsertAce(0,[Security.AccessControl.CommonAce]::new([Security.AccessControl.AceFlags]::None,[Security.AccessControl.AceQualifier]::AccessDenied,1,$user.SID,$false,$null));$deny=$descriptor.GetSddlForm([Security.AccessControl.AccessControlSections]::All)
 $aclChanged=$true;& wevtutil.exe sl $channel ('/ca:'+$deny);if($LASTEXITCODE -ne 0){throw 'Fixture owned deny ACE setter failed.'};$global:LASTEXITCODE=0
 Assert ((Get-WelaNativeChannel $channel).SecurityDescriptor -ceq $deny) 'Actual fixture-only deny descriptor readback.'
 $deniedQuery='<QueryList><Query Id="0" Path="'+$channel+'"><Select>*</Select></Query></QueryList>'
 $denied=Invoke-Public (New-Case 'denied' $deniedQuery) 1 16 -AsUser
 Assert ($denied.Status -ceq 'QueryFailed' -and $denied.Query.NativeError -eq 5 -and $denied.Matches.Count -eq 0) 'Actual standard-user native access denied.'
 Assert ((Get-WelaNativeChannel $channel).SecurityDescriptor -ceq $deny) 'Public denied read leaves prepared descriptor unchanged.'
 $passed=$true
}catch{Save 'failure.json' ([pscustomobject]@{Message=$_.Exception.Message;Stack=$_.ScriptStackTrace});throw}
finally{
 if($aclChanged){try{& wevtutil.exe sl $channel ('/ca:'+$channelBefore.SecurityDescriptor);if($LASTEXITCODE -ne 0){throw 'Original descriptor restore failed.'};$global:LASTEXITCODE=0}catch{$cleanupErrors+=$_.Exception.Message}}
 if($ownedSid){try{$current=Get-LocalUser -Name $userName -ErrorAction Stop;if($current.SID.Value -cne $ownedSid){throw 'Owned account changed identity.'};Remove-LocalUser -SID $ownedSid -ErrorAction Stop;if(Get-LocalUser -SID $ownedSid -ErrorAction SilentlyContinue){throw 'Owned account remains.'}}catch{$cleanupErrors+=$_.Exception.Message}}
 $restored=$null;try{$restored=[pscustomobject]@{Host=(Get-WelaWefQueryHost);Services=(Services);Channels=(NativeChannels);Masks=(Get-WelaEffectiveAuditPolicy);Precedence=(Get-WelaRegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' SCENoApplyLegacyAuditPolicy);Token=(Get-WelaWefQueryToken)};Save 'restored.json' $restored}catch{$cleanupErrors+=$_.Exception.Message}
 $channelsRestored=$restored -and (Key $restored.Channels) -ceq (Key $before.Channels);$servicesRestored=$restored -and (Key $restored.Services) -ceq (Key $before.Services);$policyRestored=$restored -and (Key $restored.Masks) -ceq (Key $before.Masks) -and (Key $restored.Precedence) -ceq (Key $before.Precedence);$tokenRestored=$restored -and (Get-WelaWefQueryTokenKey $restored.Token) -ceq (Get-WelaWefQueryTokenKey $before.Token)
 if(-not $channelsRestored -or -not $servicesRestored -or -not $policyRestored -or -not $tokenRestored){$cleanupErrors+='Original channel/services/policy/token differ.'}
 Save 'cleanup.json' ([pscustomobject]@{Passed=$passed;Assertions=$script:assertions;ChannelsRestored=[bool]$channelsRestored;ServicesRestored=[bool]$servicesRestored;PolicyRestored=[bool]$policyRestored;TokenRestored=[bool]$tokenRestored;AccountRemoved=[bool](-not $ownedSid -or -not(Get-LocalUser -SID $ownedSid -ErrorAction SilentlyContinue));Errors=$cleanupErrors;EventGeneration='Not tested';Forwarding='Not tested';Sources=(Get-WelaWefQuerySources)})
 if($cleanupErrors.Count){throw ('Fixture cleanup incomplete: '+($cleanupErrors -join '; '))}
}
Write-Host "WefQuery.Windows.Tests: $script:assertions actual native assertions passed; complete owned fixture cleanup."
exit 0
