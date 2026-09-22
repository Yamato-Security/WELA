$ErrorActionPreference='Stop';$script:ScriptRoot=Split-Path $PSScriptRoot -Parent
. (Join-Path $script:ScriptRoot 'scripts/WefArrival.ps1')
. (Join-Path $script:ScriptRoot 'scripts/PowerShellTranscription.ps1')
. (Join-Path $script:ScriptRoot 'scripts/TranscriptProbe.ps1')
$script:passed=0
function Assert($condition,[string]$message){if(-not $condition){throw $message};$script:passed++}
function Rejects([scriptblock]$action){$caught=$false;try{&$action|Out-Null}catch{$caught=$true};Assert $caught 'Expected refusal'}
function Clone($object){$object|ConvertTo-Json -Depth 20|ConvertFrom-Json}
$header="**********************`nWindows PowerShell transcript start`nStart time: {0:yyyyMMddHHmmss}`nUsername: {1}`nRunAs User: {2}`nConfiguration Name: {3}`nMachine: {4} ({5})`nHost Application: {6}`nProcess ID: {7}`n{8}`n**********************"
$footer="**********************`nWindows PowerShell transcript end`nEnd time: {0:yyyyMMddHHmmss}`n**********************"
$operation=[pscustomobject]@{Resources=[pscustomobject]@{TranscriptPrologue=$header;TranscriptEpilogue=$footer};Nonce=('a'*32);ProcessId=123;HeaderUser='HOST\writer';BeforeToken=[pscustomobject]@{Name='HOST\writer'};Computer='HOST';OsVersion='Microsoft Windows NT 10.0.20348.0';CommandLine='"powershell.exe" fixed';HeaderCommandLine='powershell.exe fixed';EngineVersion='5.1.20348.1000';StartOffsetMinutes=0;LaunchedUtc='2026-09-21T00:00:00.1000000Z';StartedUtc='2026-09-21T00:00:01.0000000Z';CompletedUtc='2026-09-21T00:00:02.0000000Z';ExitedUtc='2026-09-21T00:00:03.0000000Z'}
function MakeText($op){
    $begin=[string]::Format([Globalization.CultureInfo]::InvariantCulture,$op.Resources.TranscriptPrologue,@([DateTime]::new(2026,9,21,0,0,0),$op.HeaderUser,$op.BeforeToken.Name,'',$op.Computer,$op.OsVersion,$op.HeaderCommandLine,$op.ProcessId,('PSVersion: '+$op.EngineVersion+"`nPSEdition: Desktop`n")))
    $end=[string]::Format([Globalization.CultureInfo]::InvariantCulture,$op.Resources.TranscriptEpilogue,[DateTime]::new(2026,9,21,0,0,2))
    $begin+"`nWELA-TRANSCRIPT-BEGIN:"+$op.Nonce+':'+$op.ProcessId+"`nWELA-TRANSCRIPT-END:"+$op.Nonce+':'+$op.ProcessId+"`n"+$end+"`n"
}
$text=MakeText $operation
Assert (Test-WelaTranscriptProbeText $text $operation) 'Complete native transcript framing and markers match'
foreach($case in @(
    $text.Replace('Process ID: 123','Process ID: 124'),
    $text.Replace('Host Application: powershell.exe fixed','Host Application: powershell.exe other'),
    $text.Replace('RunAs User: HOST\writer','RunAs User: HOST\other'),
    $text.Replace('PSVersion: 5.1.20348.1000','PSVersion: 7.5.0'),
    $text.Replace('PSEdition: Desktop','PSEdition: Core'),
    $text.Replace('Windows PowerShell transcript end','Unfinished'),
    $text.Replace('WELA-TRANSCRIPT-BEGIN:','PS>WELA-TRANSCRIPT-BEGIN:'),
    $text.Replace('WELA-TRANSCRIPT-END:','PS>WELA-TRANSCRIPT-END:'),
    $text.Replace('Start time: 20260921000000','Start time: 20250921000000'),
    $text.Replace('End time: 20260921000002','End time: 20260921000020'),
    $text.Replace(('WELA-TRANSCRIPT-END:'+('a'*32)+':123'),('WELA-TRANSCRIPT-END:'+('b'*32)+':123')),
    $text.Replace('Configuration Name: ','Configuration Name: remote'),
    ($text+$text),
    ($text+'trailing payload')
)){Assert (-not (Test-WelaTranscriptProbeText $case $operation)) 'Incomplete, mismatched or ambiguous content has no transcript proof'}
$marker='WELA-TRANSCRIPT-END:'+('a'*32)+':123'
Assert (-not (Test-WelaTranscriptProbeText ($text.Replace($marker,($marker+"`n"+$marker))) $operation)) 'Duplicate standalone marker is rejected'
$translated=Clone $operation
$translated.Resources.TranscriptPrologue=$header.Replace('Windows PowerShell transcript start','Windows PowerShell トランスクリプト開始').Replace('Username:','ユーザー名:')
$translated.Resources.TranscriptEpilogue=$footer.Replace('Windows PowerShell transcript end','Windows PowerShell トランスクリプト終了')
Assert (Test-WelaTranscriptProbeText (MakeText $translated) $translated) 'Runtime-supplied localized resources drive matching'
foreach($encoding in @([Text.UTF8Encoding]::new($true),[Text.UnicodeEncoding]::new($false,$true),[Text.UnicodeEncoding]::new($true,$true))){$bytes=[byte[]]@($encoding.GetPreamble()+$encoding.GetBytes($text.Replace("`n","`r`n")));Assert ((ConvertFrom-WelaTranscriptProbeBytes $bytes) -ceq $text) 'Supported transcript byte encoding roundtrips'}
Rejects {ConvertFrom-WelaTranscriptProbeBytes ([byte[]]@(0xc3,0x28))}
Rejects {ConvertFrom-WelaTranscriptProbeBytes ([byte[]]@(65,0,66))}
$directory=[pscustomobject]@{Path='C:\T';Identity='id1';CreatedUtc='2026-09-21T00:00:00Z';WrittenUtc='2026-09-21T00:00:00Z';Attributes=16;Descriptor='acl';Length=0;Links=1}
$new=Clone $directory;$new.WrittenUtc='2026-09-21T00:01:00Z'
Assert ((Get-WelaTranscriptProbeObjectKey $directory -Directory) -ceq (Get-WelaTranscriptProbeObjectKey $new -Directory)) 'Directory child creation does not replace directory identity'
foreach($field in @('Identity','Descriptor','CreatedUtc','Path')){$changed=Clone $directory;$changed.$field='changed';Assert ((Get-WelaTranscriptProbeObjectKey $directory -Directory) -cne (Get-WelaTranscriptProbeObjectKey $changed -Directory)) 'Directory identity/descriptor drift is visible'}
$oldFile=Clone $directory;$oldFile.Path='C:\T\20260921\old.txt';$oldFile.Attributes=32;$oldFile.Identity='old-file';$oldFile.Length=100
$inventory=[pscustomobject]@{Folders=@([pscustomobject]@{Date='20260921';Exists=$true;Observation=$directory});Files=@($oldFile)}
$appended=Clone $inventory;$appended.Files[0].Length=200;$appended.Files[0].WrittenUtc='2026-09-21T00:01:00Z'
Assert-WelaTranscriptProbeInventory $inventory $appended;Assert $true 'Existing active transcript append is preserved without reading it'
foreach($field in @('Identity','Descriptor','CreatedUtc','Path')){$changed=Clone $inventory;$changed.Files[0].$field='changed';Rejects {Assert-WelaTranscriptProbeInventory $inventory $changed}}
$changed=Clone $inventory;$changed.Files=@();Rejects {Assert-WelaTranscriptProbeInventory $inventory $changed}
$changed=Clone $inventory;$changed.Folders[0].Exists=$false;Rejects {Assert-WelaTranscriptProbeInventory $inventory $changed}
# Pure typed-policy tests replace only local path resolution, not the policy decision.
function Resolve-WelaArrivalPath {param([string]$Path)if($Path -notmatch '^C:\\'){throw 'Fixture non-local path'};$Path}
function Value($value,$type){[pscustomobject]@{KeyExists=$true;ValueExists=$true;Value=$value;Type=$type}}
$machine=[pscustomobject]@{EnableTranscripting=(Value 1 'DWord');OutputDirectory=(Value 'C:\T' 'String');EnableInvocationHeader=(Value 1 'DWord')}
$user=[pscustomobject]@{EnableTranscripting=[pscustomobject]@{KeyExists=$false;ValueExists=$false;Value=$null;Type=$null};OutputDirectory=[pscustomobject]@{KeyExists=$false;ValueExists=$false;Value=$null;Type=$null};EnableInvocationHeader=[pscustomobject]@{KeyExists=$false;ValueExists=$false;Value=$null;Type=$null}}
$policy=@([pscustomobject]@{View='Registry64';Machine=$machine;CurrentUser=$user},[pscustomobject]@{View='Registry32';Machine=$machine;CurrentUser=$user})
Assert-WelaTranscriptProbePolicy $policy 'C:\T';Assert $true 'Known enabled matching machine policy accepted'
foreach($field in @('EnableTranscripting','OutputDirectory','EnableInvocationHeader')){$changed=Clone $policy;$changed[0].Machine.$field.Type='Unknown';$changed[1].Machine.$field.Type='Unknown';Rejects {Assert-WelaTranscriptProbePolicy $changed 'C:\T'}}
$changed=Clone $policy;$changed[0].Machine.EnableTranscripting.Value=0;$changed[1].Machine.EnableTranscripting.Value=0;Rejects {Assert-WelaTranscriptProbePolicy $changed 'C:\T'}
Rejects {Assert-WelaTranscriptProbePolicy $policy 'C:\Other'}
$changed=Clone $policy;$changed[1].Machine.OutputDirectory.Value='C:\Other';Rejects {Assert-WelaTranscriptProbePolicy $changed 'C:\T'}
Rejects {Assert-WelaTranscriptProbePolicy @($policy[0]) 'C:\T'}
$engine=(Get-Process -Id $PID).Path
foreach($case in @(@{Args=@('transcript-probe','-Help');Exit=0},@{Args=@('transcript-probe','-Help','-Auto');Exit=1},@{Args=@('transcript-probe','-Help','-TranscriptDirectory','C:\T');Exit=1},@{Args=@('transcript-probe','-Help','-DryRun');Exit=1},@{Args=@('help','-TranscriptProbeAction','Run');Exit=1})){
    $old=$ErrorActionPreference;$ErrorActionPreference='Continue';try{$output=&$engine -NoProfile -File (Join-Path $script:ScriptRoot 'WELA.ps1') @($case.Args) 2>&1;$code=$LASTEXITCODE}finally{$ErrorActionPreference=$old}
    Assert ($code -eq $case.Exit) ('CLI boundary '+($case.Args -join ' ')+': '+($output|Out-String))
}
$global:LASTEXITCODE=0;Write-Host "Transcript probe fixtures passed: $script:passed"
