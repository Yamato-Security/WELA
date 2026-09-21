$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent
Import-Module "$repo/modules/AuditProfiles.psm1" -Force
. "$repo/scripts/WefArrival.ps1"
. "$repo/scripts/WecUpdate.ps1"
. "$repo/scripts/FailedLogonProbe.ps1"
Add-Type -Path "$repo/scripts/FailedLogonProbeNative.cs" -ErrorAction Stop
$script:count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Reject($Code,$Pattern){$message='';try{&$Code|Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern, got $message"}
function Clone($Value){ConvertFrom-WelaArrivalJson ($Value|ConvertTo-Json -Depth 24 -Compress)}
$token=[pscustomobject][ordered]@{UserSid='S-1-5-21-1-2-3-1001';AuthenticationId='0000000000000123';TokenId='0000000000001000';ModifiedId='0000000000001001';ElevatedAdministrator=$true;TokenType='Primary';Impersonation='Absent';GroupSids=@('S-1-1-0','S-1-5-32-544');GroupCount=2;PrivilegeCount=12;ProcessId=1234}
$state=[pscustomobject][ordered]@{Host=[pscustomobject]@{Computer='LAB';DomainJoined=$false;Domain='WORKGROUP'};Token=$token;AuditPolicies=@{'0cce9215-69ae-11d9-bed3-505054503030'=2};Precedence=[pscustomobject]@{ValueExists=$true;Type='DWord';Value=1};Channel=[pscustomobject]@{Enabled=$true};Engine='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe';Sources='fixed-sources'}
$nonce='abcdef0123456789abcdef0123456789ab';$worker=Clone $token;$worker.ProcessId=456;$worker.TokenId='0000000000002000'
$operation=[pscustomobject]@{Nonce=$nonce;ProcessId=456;Executable=$state.Engine;BeforeToken=$worker;AfterToken=(Clone $worker);SecurityRecordIdBefore=100;Attempt=[pscustomobject]@{UserName=('WL'+$nonce.Substring(0,18));Domain='.';MissingAccountStatus=2221;LogonType=3;LogonProvider=2;Succeeded=$false;NativeError=1326;Clock='GetSystemTimePreciseAsFileTime';StartedUtc='2025-01-02T03:04:05.1234500Z';CompletedUtc='2025-01-02T03:04:06.1234500Z'}}
$launch=[DateTimeOffset]'2025-01-02T03:04:05Z';$observed=[DateTimeOffset]'2025-01-02T03:04:07Z'
Assert-WelaFailedLogonOperation $operation $state $nonce 456 $launch $observed
Assert $true 'A fixed typed receipt under the same inherited authorization is accepted.'
foreach($field in @('UserName','Domain','MissingAccountStatus','LogonType','LogonProvider','Succeeded','NativeError','Clock','StartedUtc','CompletedUtc','Nonce','ProcessId','Executable','Token','TokenType')){
 $bad=Clone $operation
 switch($field){
 UserName {$bad.Attempt.UserName='Administrator'}
 Domain {$bad.Attempt.Domain='example.test'}
 MissingAccountStatus {$bad.Attempt.MissingAccountStatus=0}
 LogonType {$bad.Attempt.LogonType=2}
 LogonProvider {$bad.Attempt.LogonProvider=0}
 Succeeded {$bad.Attempt.Succeeded=$true}
 NativeError {$bad.Attempt.NativeError='1326'}
 Clock {$bad.Attempt.Clock='DateTime.UtcNow'}
 StartedUtc {$bad.Attempt.StartedUtc='2025-01-02T03:04:04.9999999Z'}
 CompletedUtc {$bad.Attempt.CompletedUtc='2025-01-02T03:04:07.0000001Z'}
 Nonce {$bad.Nonce='f'*32}
 ProcessId {$bad.ProcessId=457}
 Executable {$bad.Executable='C:\other.exe'}
 Token {$bad.AfterToken.ModifiedId='0000000000001002'}
 TokenType {$bad.BeforeToken.GroupCount='2'}
 }
 Reject {Assert-WelaFailedLogonOperation $bad $state $nonce 456 $launch $observed} 'Unexpected|interval|token|observation'
}
foreach($api in @('LogonUserW','NetUserGetInfo','GetSystemTimePreciseAsFileTime')){
 $import=[Wela.FailedLogonProbe.Native].GetMethod($api,[Reflection.BindingFlags]'NonPublic,Static').GetCustomAttributes([Runtime.InteropServices.DllImportAttribute],$false)[0]
 Assert ($import.ExactSpelling -and $import.EntryPoint -ceq $api) ('Exact native binding '+$api)
}
Reject {[Wela.FailedLogonProbe.Native]::Run('Administrator')} 'GUID nonce'
$xml='<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/><EventID>4625</EventID><Version>0</Version><Keywords>0x8010000000000000</Keywords><EventRecordID>101</EventRecordID><Channel>Security</Channel><Computer>LAB</Computer><TimeCreated SystemTime="2025-01-02T03:04:05.5000000Z"/></System><EventData><Data Name="SubjectUserSid">S-1-5-21-1-2-3-1001</Data><Data Name="SubjectLogonId">0x123</Data><Data Name="TargetUserSid">S-1-0-0</Data><Data Name="TargetUserName">WLabcdef0123456789ab</Data><Data Name="TargetDomainName">LAB</Data><Data Name="Status">0xc000006d</Data><Data Name="SubStatus">0xc0000064</Data><Data Name="LogonType">3</Data><Data Name="AuthenticationPackageName">MICROSOFT_AUTHENTICATION_PACKAGE_V1_0</Data><Data Name="ProcessName">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name="ProcessId">0x1c8</Data></EventData></Event>'
Assert (Test-WelaFailedLogonEvent $xml $operation $state) 'Exact synthetic4625 matches.'
foreach($edge in @(@('03:04:05.1234500Z',$true),@('03:04:06.1234500Z',$true),@('03:04:05.1234499Z',$false),@('03:04:06.1234501Z',$false))){Assert ((Test-WelaFailedLogonEvent $xml.Replace('03:04:05.5000000Z',$edge[0]) $operation $state) -eq $edge[1]) 'Exact100ns operation boundary.'}
foreach($pair in @(@('4625','4624'),@('>0</Version>','>1</Version>'),@('WLabcdef0123456789ab','Administrator'),@('0xc0000064','0xc000006a'),@('0xc000006d','0x0'),@('>3</Data>','>2</Data>'),@('>MICROSOFT_AUTHENTICATION_PACKAGE_V1_0<','>Kerberos<'),@('>MICROSOFT_AUTHENTICATION_PACKAGE_V1_0<','>NTLM<'),@('0x1c8','0x1c9'),@('0x123','0x124'),@('S-1-5-21-1-2-3-1001','S-1-5-18'),@('>LAB<','>OTHER<'),@('S-1-0-0','S-1-5-18'),@('>101<','>100<'),@('0x8010000000000000','0x8020000000000000'),@('>Security<','>Application<'),@('powershell.exe','other.exe'),@('54849625-5478-4994-a5ba-3e3b0328c30d','54849625-5478-4994-a5ba-3e3b0328c30e'))){$bad=$xml.Replace($pair[0],$pair[1]);Assert ($bad -cne $xml) 'Mutation changes fixture';Assert (-not(Test-WelaFailedLogonEvent $bad $operation $state)) ('Mismatch refused '+$pair[0])}
Assert (-not(Test-WelaFailedLogonEvent $xml.Replace('</EventData>','<Data Name="LogonType">3</Data></EventData>') $operation $state)) 'Duplicate payload refused.'
Assert (-not(Test-WelaFailedLogonEvent $xml.Replace('</System>','<EventID>4625</EventID></System>') $operation $state)) 'Duplicate System field refused.'
Assert (-not(Test-WelaFailedLogonEvent ('<!DOCTYPE Event [<!ENTITY x "LAB">]>'+$xml.Replace('>LAB<','>&x;<')) $operation $state)) 'DTD refused.'
$null=Get-WelaFailedLogonStateKey $state
foreach($mask in @(0,1,4,'2')){$bad=Clone $state;$bad.AuditPolicies=@{'0cce9215-69ae-11d9-bed3-505054503030'=$mask};Reject {Get-WelaFailedLogonStateKey $bad} 'failure auditing'}
$bad=Clone $state;$bad.Precedence.Type='String';Reject {Get-WelaFailedLogonStateKey $bad} 'failure auditing'
$bad=Clone $state;$bad.Channel.Enabled=$false;Reject {Get-WelaFailedLogonStateKey $bad} 'failure auditing'
Reject {Invoke-WelaFailedLogonProbe -Action Run} 'requires a new'
Reject {Invoke-WelaFailedLogonProbe -OutputPath 'unused'} 'Plan creates no files'
# Production orchestration with only native boundaries mocked; no authentication here.
$script:mode='Success';$script:reads=0;$script:attempts=0
function Get-WelaFailedLogonState {$script:reads++;$copy=Clone $state;$copy.AuditPolicies=@{'0cce9215-69ae-11d9-bed3-505054503030'=2};if($script:mode -eq 'Blocked'){$copy.AuditPolicies['0cce9215-69ae-11d9-bed3-505054503030']=0};if($script:mode -eq 'Drift' -and $script:reads -gt 1){$copy.Sources='changed'};$copy}
function Start-WelaFailedLogonAttempt {param($State,$OutputPath);$script:attempts++;$operation}
function Read-WelaFailedLogonEvents {param($Operation);if($script:mode -eq 'ReadError'){throw 'native read failed'};$events=@($xml);if($script:mode -eq 'Duplicate'){$events+= $xml};[pscustomobject]@{Xml=$events;Capped=($script:mode -eq 'Cap')}}
function Get-WelaFailedLogonWatermark {if($script:mode -eq 'Clear'){99}else{101}}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-failed-logon-fixtures-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $temp
try{
 $plan=Invoke-WelaFailedLogonProbe;Assert ($plan.Status -eq 'PrerequisitesObserved' -and $script:attempts -eq 0) 'Plan never authenticates.'
 foreach($mode in @('Success','Blocked','Cap','ReadError','Drift','Clear','Duplicate')){
  $script:mode=$mode;$script:reads=0;$script:attempts=0;$dir=Join-Path $temp $mode
  $result=Invoke-WelaFailedLogonProbe -Action Run -OutputPath $dir -TimeoutSeconds 1
  $manifest=ConvertFrom-WelaArrivalJson ([IO.File]::ReadAllText((Join-Path $dir 'manifest.json')))
  Assert ($manifest.ReadyRuleCredit -eq 0 -and $manifest.PolicyChanges -eq 0 -and $manifest.AccountChanges -eq 0) 'No audit or readiness claim.'
  Assert ($null -ne $manifest.After) 'Final state retained.'
  foreach($artifact in $manifest.Artifacts){Assert ($artifact.Sha256 -ceq (Get-FileHash -LiteralPath (Join-Path $dir $artifact.Name)).Hash.ToLowerInvariant()) 'Exact artifact hash.'}
  if($mode -eq 'Success'){Assert ($result.Status -eq 'LocalFailedLogonObserved' -and $result.Matches -eq 1 -and $result.ExitCode -eq 0 -and $script:attempts -eq 1) 'Only one worker attempt.'}else{Assert ($result.Status -eq 'Unverified' -and $result.ExitCode -eq 1 -and $result.Diagnostic) ('Unverified '+$mode)}
  if($mode -eq 'Blocked'){Assert ($script:attempts -eq 0) 'Missing prerequisites never attempt authentication.'}
 }
}finally{Remove-Item -LiteralPath $temp -Recurse -Force}
Write-Host "PASS: $script:count failed-logon fixtures; authentication was mocked."
$global:LASTEXITCODE=0
