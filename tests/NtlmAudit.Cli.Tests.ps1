$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent;$engine=(Get-Process -Id $PID).Path;$count=0
$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-ntlm-audit-cli-'+[guid]::NewGuid().ToString('N'))
$cases=@(
 @{Args=@('ntlm-auditing','-Help');Code=0;Pattern='preserves all authentication restrictions'},
 @{Args=@('configure','-NtlmAuditAction','Configure');Code=1;Pattern='require ntlm-auditing'},
 @{Args=@('audit','-NtlmAuditScope','Incoming');Code=1;Pattern='require ntlm-auditing'},
 @{Args=@('ntlm-auditing','-NtlmAuditAction','Configure');Code=1;Pattern='requires explicit NtlmAuditScope'},
 @{Args=@('ntlm-auditing','-OutgoingNtlmMode','Deny');Code=1;Pattern='dedicated options'},
 @{Args=@('ntlm-auditing','-Role','DomainController');Code=1;Pattern='dedicated options'},
 @{Args=@('ntlm-auditing','-Build','26100');Code=1;Pattern='dedicated options'},
 @{Args=@('ntlm-auditing','-Profile','wela-2.2.0');Code=1;Pattern='dedicated options'},
 @{Args=@('ntlm-auditing','-Auto');Code=1;Pattern='require NtlmAuditAction Configure'},
 @{Args=@('ntlm-auditing','-DryRun');Code=1;Pattern='require NtlmAuditAction Configure'},
 @{Args=@('ntlm-auditing','-BackupPath',$root);Code=1;Pattern='require NtlmAuditAction Configure'},
 @{Args=@('ntlm-auditing','-Help','-NtlmAction','Configure');Code=1;Pattern='dedicated options'},
 @{Args=@('ntlm-auditing','-NtlmAuditScope','Incoming','-NtlmAuditAction','Configure','-Typo');Code=1;Pattern='Unsupported trailing arguments'}
)
foreach($case in $cases){$prior=$ErrorActionPreference;try{$ErrorActionPreference='Continue';$text=@(&$engine -NoLogo -NoProfile -NonInteractive -File "$repo/WELA.ps1" @($case.Args) 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$prior};if(($code -eq 0) -ne ($case.Code -eq 0) -or ($text -join "`n") -notmatch $case.Pattern){throw "CLI failed: $($case.Args -join ' ') -> $code / $($text -join ' ')"};$count++}
if(Test-Path $root){throw 'Refused CLI input created unexpected output.'}
Write-Host "PASS: $count scoped NTLM CLI guards."
exit 0
