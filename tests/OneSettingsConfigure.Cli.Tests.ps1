# Public option isolation; these tests do not claim native configuration evidence.
$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent;$engine=(Get-Process -Id $PID).Path;$count=0
$unused=Join-Path ([IO.Path]::GetTempPath()) ('wela-onesettings-cli-'+[guid]::NewGuid().ToString('N'))
$cases=@(
 @{Args=@('audit-notifications','-Help');Code=0;Pattern='EnablePrivacyChannel'},
 @{Args=@('audit-notifications','-NotificationAction','Configure','-NotificationControl','OneSettings','-EnablePrivacyChannel','-Auto','-BackupPath',$unused,'-WhatIf');Code=1;Pattern='No command was run'},
 @{Args=@('audit-notifications','-NotificationAction','Configure','-NotificationControl','OneSettings','-EnablePrivacyChannel','-Auto','-UnexpectedOption');Code=1;Pattern='No command was run'},
 @{Args=@('audit-notifications','-NotificationAction','Configure','-Auto');Code=1;Pattern='explicit NotificationControl'},
 @{Args=@('audit-notifications','-NotificationControl','SecurityWarning','-EnablePrivacyChannel');Code=1;Pattern='requires the OneSettings'},
 @{Args=@('audit-notifications','-NotificationAction','Plan','-DryRun');Code=1;Pattern='DryRun'},
 @{Args=@('audit-notifications','-Help','-Build','20348');Code=1;Pattern='accepts only notification'},
 @{Args=@('audit-notifications','-Help','-Profile','wela-2.2.0');Code=1;Pattern='accepts only notification'},
 @{Args=@('channel-settings','-Help','-EnablePrivacyChannel');Code=1;Pattern='Notification options require'},
 @{Args=@('configure','-NotificationControl','OneSettings','-Auto');Code=1;Pattern='Notification options require'}
)
foreach($case in $cases){$old=$ErrorActionPreference;try{$ErrorActionPreference='Continue';$output=&$engine -NoLogo -NoProfile -NonInteractive -File "$repo/WELA.ps1" @($case.Args) 2>&1|Out-String;$code=$LASTEXITCODE}finally{$ErrorActionPreference=$old};if($code -ne $case.Code -or $output -notmatch $case.Pattern){throw "Public option case failed: $($case.Args -join ' ') [$code] $output"};$count++}
if(Test-Path -LiteralPath $unused){throw 'Unsupported preview created a journal directory.'};$count++
Write-Host "PASS: $count public OneSettings option guards."
$global:LASTEXITCODE=0
