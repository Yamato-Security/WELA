$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent;$engine=(Get-Process -Id $PID).Path;$count=0
$cases=@(
 @{Args=@('failed-logon-probe','-Help');Code=0;Pattern='nonexistent local account'},
 @{Args=@('configure','-FailedLogonAction','Run','-Auto');Code=1;Pattern='require failed-logon-probe'},
 @{Args=@('failed-logon-probe','-Help','-Auto');Code=1;Pattern='only dedicated'},
 @{Args=@('failed-logon-probe','-Help','-DryRun');Code=1;Pattern='only dedicated'},
 @{Args=@('failed-logon-probe','-Help','-ResultsPath','unused');Code=1;Pattern='only dedicated'},
 @{Args=@('failed-logon-probe','-Help','-Profile','wela-2.2.0');Code=1;Pattern='only dedicated'},
 @{Args=@('failed-logon-probe','-FailedLogonAction','Run');Code=1;Pattern='requires a new'},
 @{Args=@('failed-logon-probe','-FailedLogonOutputPath','unused');Code=1;Pattern='Plan creates no files'})
foreach($case in $cases){$ErrorActionPreference='Continue';$output=& $engine -NoProfile -NonInteractive -File "$repo/WELA.ps1" @($case.Args) 2>&1|Out-String;$code=$LASTEXITCODE;$ErrorActionPreference='Stop';if($code -ne $case.Code -or $output -notmatch $case.Pattern){throw "CLI failed: $($case.Args -join ' ') [$code] $output"};$count++}
Write-Host "PASS: $count failed-logon public CLI checks."
$global:LASTEXITCODE=0
