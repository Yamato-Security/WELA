$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent;$engine=(Get-Process -Id $PID).Path;$count=0
$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-ntlm-cli-'+[guid]::NewGuid().ToString('N'))
$cases=@(
 @{Args=@('process-commandline','-ProcessCommandlineAction','Configure','-DryRun','-Help');Code=0;Pattern='Enables only'},
 @{Args=@('process-commandline','-Help');Code=0;Pattern='Enables only'},
 @{Args=@('configure','-ProcessCommandlineAction','Configure');Code=1;Pattern='requires process-commandline'},
 @{Args=@('process-commandline','-OutgoingNtlmMode','Deny');Code=1;Pattern='dedicated options'},
 @{Args=@('process-commandline','-Role','Client');Code=1;Pattern='dedicated options'},
 @{Args=@('process-commandline','-Profile','wela-2.2.0');Code=1;Pattern='dedicated options'},
 @{Args=@('process-commandline','-Auto');Code=1;Pattern='options require'},
 @{Args=@('process-commandline','-DryRun');Code=1;Pattern='options require'},
 @{Args=@('process-commandline','-BackupPath',$root);Code=1;Pattern='options require'},
 @{Args=@('process-commandline','-Help','-ProviderAction','Configure');Code=1;Pattern='dedicated options'},
 @{Args=@('process-commandline','-ProcessCommandlineAction','Configure','-Typo');Code=1;Pattern='Unsupported trailing arguments'}
)
foreach($case in $cases){$prior=$ErrorActionPreference;try{$ErrorActionPreference='Continue';$text=@(&$engine -NoLogo -NoProfile -NonInteractive -File "$repo/WELA.ps1" @($case.Args) 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$prior};if(($code -eq 0) -ne ($case.Code -eq 0) -or ($text -join "`n") -notmatch $case.Pattern){throw "CLI failed: $($case.Args -join ' ') -> $code / $($text -join ' ')"};$count++}
if(Test-Path $root){throw 'Refused CLI input created unexpected output.'}
Write-Host "PASS: $count scoped process command-line CLI guards."
exit 0
