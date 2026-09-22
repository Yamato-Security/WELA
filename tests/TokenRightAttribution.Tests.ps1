$ErrorActionPreference='Stop'
. "$PSScriptRoot/TokenRightAttributionEvidence.ps1"
$count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
$start=[DateTime]::Parse('2026-09-22T00:00:00Z').ToFileTimeUtc()
$context=[pscustomobject]@{Task=13570;Computers=@('HOST','HOST.example.test');Watermark=100;ProcessId=1234;ProcessName='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe';Sid='S-1-5-21-1-2-3-500';AuthenticationId='0x123';DisableStartedFileTime=$start;DisableReturnedFileTime=$start+100000;RestoreStartedFileTime=$start+200000;RestoreReturnedFileTime=$start+300000;PrivilegeVerificationCompletedFileTime=$start+300000;OperationCompletedFileTime=$start+300000}
$xml=@'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/><EventID>4703</EventID><Version>0</Version><Level>0</Level><Task>13570</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="2026-09-22T00:00:00.0050000Z"/><EventRecordID>101</EventRecordID><Channel>Security</Channel><Computer>HOST.example.test</Computer></System><EventData><Data Name="SubjectUserSid">S-1-5-21-1-2-3-500</Data><Data Name="SubjectLogonId">0x123</Data><Data Name="TargetUserSid">S-1-5-21-1-2-3-500</Data><Data Name="TargetLogonId">0x123</Data><Data Name="ProcessName">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name="ProcessId">0x4d2</Data><Data Name="EnabledPrivilegeList">-</Data><Data Name="DisabledPrivilegeList">SeDebugPrivilege</Data></EventData></Event>
'@
$result=Get-WelaTokenAttributionMatch $xml $context
Assert ($result.Direction -ceq 'Disable' -and $result.RecordId -eq 101) 'Exact fixed disable is attributable.'
$restore=$xml.Replace('>101<','>102<').Replace('00.0050000Z','00.0250000Z').Replace('Name="EnabledPrivilegeList">-','Name="EnabledPrivilegeList">SeDebugPrivilege').Replace('Name="DisabledPrivilegeList">SeDebugPrivilege','Name="DisabledPrivilegeList">-')
Assert ((Get-WelaTokenAttributionMatch $restore $context).Direction -ceq 'Restore') 'Exact fixed restoration is independently attributable.'
foreach($case in @(
 @('Microsoft-Windows-Security-Auditing','Other-Provider'),@('54849625','54849626'),@('<EventID>4703','<EventID>4704'),@('<Version>0','<Version>1'),@('<Level>0','<Level>1'),@('<Task>13570','<Task>13571'),@('<Opcode>0','<Opcode>1'),@('0x8020000000000000','0x8010000000000000'),@('<Channel>Security','<Channel>ForwardedEvents'),@('HOST.example.test','HOST.attacker.test'),@('>101<','>100<'),@('>101<','>0<'),@('>101<','>true<'),@('>0x4d2<','>0x4d3<'),@('>0x4d2<','>1234<'),@('powershell.exe','pwsh.exe'),@('S-1-5-21-1-2-3-500','S-1-5-21-1-2-3-501'),@('>0x123<','>0x124<'),@('>SeDebugPrivilege<','>SeDebugPrivilege SeBackupPrivilege<'),@('>SeDebugPrivilege<','>SeChangeNotifyPrivilege<'),@('>SeDebugPrivilege<','>sedebugprivilege<'),@('00.0050000Z','00.0350000Z'),@('00.0050000Z','00.0050000+00:00'),@('http://schemas.microsoft.com/win/2004/08/events/event','urn:wrong')
)){Assert ($null -eq (Get-WelaTokenAttributionMatch ($xml.Replace($case[0],$case[1])) $context)) ('Mismatched event rejected: '+$case[0])}
foreach($field in @('SubjectUserSid','SubjectLogonId','TargetUserSid','TargetLogonId')){
 $doc=[xml]$xml;$node=@($doc.Event.EventData.Data|Where-Object{$_.Name -ceq $field})[0];$node.InnerText+='9'
 Assert ($null -eq (Get-WelaTokenAttributionMatch $doc.OuterXml $context)) ('Independent mismatched identity rejected: '+$field)
}
$doc=[xml]$xml;$node=$doc.Event.EventData.Data[0];$null=$doc.Event.EventData.AppendChild($node.CloneNode($true));Assert ($null -eq (Get-WelaTokenAttributionMatch $doc.OuterXml $context)) 'Duplicate data field refused.'
$doc=[xml]$xml;$node=$doc.Event.System.EventID;$null=$doc.Event.System.AppendChild($doc.Event.System.SelectSingleNode('*[local-name()="EventID"]').CloneNode($true));Assert ($null -eq (Get-WelaTokenAttributionMatch $doc.OuterXml $context)) 'Duplicate header field refused.'
$doc=[xml]$xml;$null=$doc.Event.System.RemoveChild($doc.Event.System.SelectSingleNode('*[local-name()="Task"]'));Assert ($null -eq (Get-WelaTokenAttributionMatch $doc.OuterXml $context)) 'Missing native task refused.'
foreach($text in @((' '+$xml).PadRight(65537),('<!DOCTYPE Event [<!ENTITY payload "owned">]>'+$xml))){$rejected=$false;try{$null=Get-WelaTokenAttributionMatch $text $context}catch{$rejected=$true};Assert $rejected 'Oversized XML and DTD refuse explicitly.'}
# Regex operations must not corrupt the event accumulator (PowerShell owns $Matches).
$attributedEvents=@();foreach($text in @($xml,$restore)){$m=Get-WelaTokenAttributionMatch $text $context;if($m){$attributedEvents+=@($m)}}
Assert ($attributedEvents.Count -eq 2 -and @($attributedEvents|Select-Object -ExpandProperty RecordId -Unique).Count -eq 2) 'Two directions survive regex correlation as distinct records.'
Import-Module "$PSScriptRoot/../modules/AuditProfiles.psm1" -Force
Import-Module "$PSScriptRoot/../modules/AuditCatalog.psm1" -Force
$catalog=(Import-WelaAuditProfiles).catalog
$token=@($catalog|Where-Object id -CEQ 'Token Right Adjusted Events')
Assert ($token.Count -eq 1 -and $token[0].guid -ceq '0CCE924A-69AE-11D9-BED3-505054503030') 'Native attribution is bound to the canonical token GUID, never RPC.'
$review=Get-WelaEventMappingReview @(Import-Csv "$PSScriptRoot/../config/eid_subcategory_mapping.csv") $catalog 4703
Assert ($review.State -ceq 'Conditional' -and $review.Candidates.Count -eq 2 -and -not $review.DetectionReady) 'Build-specific generation never erases historical candidates or grants Sigma credit.'
Assert-WelaTokenAttributionTimes $context ($start-100) ($start+400000)
Assert $true 'Typed monotonic native timing accepted.'
foreach($field in @('DisableStartedFileTime','DisableReturnedFileTime','RestoreStartedFileTime','RestoreReturnedFileTime','PrivilegeVerificationCompletedFileTime','OperationCompletedFileTime')){
 foreach($bad in @($true,'134345000000000000',0L,($start-200),($start+500000))){
  $copy=$context|ConvertTo-Json -Depth 8|ConvertFrom-Json;$copy.$field=$bad;$rejected=$false
  try{Assert-WelaTokenAttributionTimes $copy ($start-100) ($start+400000)}catch{$rejected=$true}
  Assert $rejected ('Malformed or out-of-envelope native timestamp refused: '+$field)
 }
}
$copy=$context|ConvertTo-Json -Depth 8|ConvertFrom-Json;$copy.RestoreStartedFileTime=$start+50000;$rejected=$false;try{Assert-WelaTokenAttributionTimes $copy ($start-100) ($start+400000)}catch{$rejected=$true};Assert $rejected 'Nonmonotonic in-envelope timestamps refused.'
$definitions=@([pscustomobject]@{Name='SE_ADT_DETAILEDTRACKING_TOKENRIGHTADJ';Value=13317})
$publisher='<provider name="Microsoft-Windows-Security-Auditing" guid="54849625-5478-4994-a5ba-3e3b0328c30d"><tasks><task name="SE_ADT_DETAILEDTRACKING_TOKENRIGHTADJ" value="13317"/></tasks><events><event value="4703" version="0" task="0"/></events></provider>'
Assert ((Get-WelaTokenAttributionTask $definitions $publisher) -eq 13317) 'Independent native task definition and publisher XML bind runtime task despite generic event declaration0.'
foreach($bad in @(@(),@($definitions[0],$definitions[0]),@([pscustomobject]@{Name=$definitions[0].Name;Value=$true}),@([pscustomobject]@{Name=$definitions[0].Name;Value='13317'}),@([pscustomobject]@{Name=$definitions[0].Name;Value=13570}),@([pscustomobject]@{Name='Wrong';Value=13317}))){$rejected=$false;try{$null=Get-WelaTokenAttributionTask $bad $publisher}catch{$rejected=$true};Assert $rejected 'Missing/duplicate/mistyped/wrong native task definition refuses.'}
foreach($text in @($publisher.Replace('13317','13570'),$publisher.Replace('TOKENRIGHTADJ','OTHER'),$publisher.Replace('54849625','54849626'),$publisher.Replace('<tasks>','<other>').Replace('</tasks>','</other>'))){$rejected=$false;try{$null=Get-WelaTokenAttributionTask $definitions $text}catch{$rejected=$true};Assert $rejected 'Native publisher task/identity mismatch refuses.'}
Write-Host "PASS: $count strict token attribution and catalog checks."
