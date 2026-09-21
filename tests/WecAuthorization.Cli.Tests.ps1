$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent;$engine=(Get-Process -Id $PID).Path;$count=0
$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-auth-cli-'+[guid]::NewGuid().ToString('N'))
$cases=@(
 @{Args=@('wec-authorization','-Help');Code=0;Pattern='already disabled'},
 @{Args=@('configure','-WecAuthorizationAction','Apply','-Auto');Code=1;Pattern='require wec-authorization'},
 @{Args=@('wec-authorization','-Auto');Code=1;Pattern='only dedicated'},
 @{Args=@('wec-authorization','-DryRun');Code=1;Pattern='only dedicated'},
 @{Args=@('wec-authorization','-WhatIf');Code=1;Pattern='only dedicated'},
 @{Args=@('wec-authorization','-Typo');Code=1;Pattern='only dedicated'},
 @{Args=@('wec-authorization','-Help','-WecStateDesired','Enabled');Code=1;Pattern='only dedicated'},
 @{Args=@('wec-authorization','-ResultsPath',$root);Code=1;Pattern='only dedicated'},
 @{Args=@('wec-authorization','-WecAuthorizationOutputPath',$root);Code=1;Pattern='Plan requires'},
 @{Args=@('wec-authorization','-WecAuthorizationId','test','-WecAuthorizationSourceSid','S-1-5-21-1-2-3-4','-WecAuthorizationPlanPath','missing','-WecAuthorizationOutputPath',$root);Code=1;Pattern='Plan requires'},
 @{Args=@('wec-authorization','-WecAuthorizationAction','Apply','-WecAuthorizationOutputPath',$root);Code=1;Pattern='reviewed plan'},
 @{Args=@('wec-authorization','-WecAuthorizationAction','Apply','-WecAuthorizationPlanPath','missing','-WecAuthorizationPlanHash',('a'*64),'-WecAuthorizationId','test','-WecAuthorizationOutputPath',$root);Code=1;Pattern='only'}
)
foreach($case in $cases){$prior=$ErrorActionPreference;try{$ErrorActionPreference='Continue';$text=@(&$engine -NoLogo -NoProfile -NonInteractive -File "$repo/WELA.ps1" @($case.Args) 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$prior};if(($code -eq 0) -ne ($case.Code -eq 0) -or ($text -join "`n") -notmatch $case.Pattern){throw "CLI failed: $($case.Args -join ' ') -> $code / $($text -join ' ')"};$count++}
if(Test-Path $root){throw 'Refused CLI input unexpectedly created output.'}
Write-Host "PASS: $count WEC authorization public CLI guards."
$global:LASTEXITCODE=0
