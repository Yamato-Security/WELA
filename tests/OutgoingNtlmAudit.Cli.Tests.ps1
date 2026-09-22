$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent;$engine=(Get-Process -Id $PID).Path;$count=0
$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-ntlm-cli-'+[guid]::NewGuid().ToString('N'))
$cases=@(
 @{Args=@('outgoing-ntlm','-Help');Code=0;Pattern='Changes only'},
 @{Args=@('configure','-NtlmAction','Configure');Code=1;Pattern='requires outgoing-ntlm'},
 @{Args=@('outgoing-ntlm','-OutgoingNtlmMode','Deny');Code=1;Pattern='enforcement is not accepted'},
 @{Args=@('outgoing-ntlm','-Role','Client');Code=1;Pattern='dedicated options'},
 @{Args=@('outgoing-ntlm','-Profile','wela-2.2.0');Code=1;Pattern='dedicated options'},
 @{Args=@('outgoing-ntlm','-Auto');Code=1;Pattern='require NtlmAction Configure'},
 @{Args=@('outgoing-ntlm','-DryRun');Code=1;Pattern='require NtlmAction Configure'},
 @{Args=@('outgoing-ntlm','-BackupPath',$root);Code=1;Pattern='require NtlmAction Configure'},
 @{Args=@('outgoing-ntlm','-Help','-ProviderAction','Configure');Code=1;Pattern='dedicated options'},
 @{Args=@('outgoing-ntlm','-NtlmAction','Configure','-Typo');Code=1;Pattern='Unsupported trailing arguments'}
)
foreach($case in $cases){$prior=$ErrorActionPreference;try{$ErrorActionPreference='Continue';$text=@(&$engine -NoLogo -NoProfile -NonInteractive -File "$repo/WELA.ps1" @($case.Args) 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$prior};if(($code -eq 0) -ne ($case.Code -eq 0) -or ($text -join "`n") -notmatch $case.Pattern){throw "CLI failed: $($case.Args -join ' ') -> $code / $($text -join ' ')"};$count++}
if(Test-Path $root){throw 'Refused CLI input created unexpected output.'}
Write-Host "PASS: $count scoped outgoing NTLM CLI guards."
exit 0
