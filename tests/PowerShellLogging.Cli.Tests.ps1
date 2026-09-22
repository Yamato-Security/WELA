$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent;$engine=(Get-Process -Id $PID).Path;$count=0
$cases=@(
 @{Args=@('powershell-logging','-Help');Code=0;Pattern='Windows PowerShell 5.1'},
 @{Args=@('configure','-PowerShellLoggingAction','Configure');Code=1;Pattern='require powershell-logging'},
 @{Args=@('audit','-PowerShellLoggingControl','ScriptBlock');Code=1;Pattern='require powershell-logging'},
 @{Args=@('powershell-logging','-PowerShellLoggingAction','Configure');Code=1;Pattern='explicit PowerShellLoggingControl'},
 @{Args=@('powershell-logging','-PowerShellLoggingAction','Plan');Code=1;Pattern='explicit PowerShellLoggingControl'},
 @{Args=@('powershell-logging','-PowerShellLoggingAction','Configure','-PowerShellLoggingControl','Module');Code=1;Pattern='PowerShellLoggingModuleName'},
 @{Args=@('powershell-logging','-PowerShellLoggingControl','ScriptBlock','-PowerShellLoggingModuleName','Microsoft.PowerShell.Utility');Code=1;Pattern='Module selection'},
 @{Args=@('powershell-logging','-Role','DomainController');Code=1;Pattern='dedicated options'},
 @{Args=@('powershell-logging','-Profile','wela-2.2.0');Code=1;Pattern='dedicated options'},
 @{Args=@('powershell-logging','-Auto');Code=1;Pattern='PowerShellLoggingAction'},
 @{Args=@('powershell-logging','-DryRun');Code=1;Pattern='PowerShellLoggingAction'},
 @{Args=@('powershell-logging','-PowerShellLoggingControl','Module','-PowerShellLoggingModuleName','Mod*');Code=1;Pattern='literal module'},
 @{Args=@('powershell-logging','-Help','-Typo');Code=1;Pattern='Unsupported trailing arguments'}
)
foreach($case in $cases){$prior=$ErrorActionPreference;try{$ErrorActionPreference='Continue';$output=@(&$engine -NoLogo -NoProfile -NonInteractive -File "$repo/WELA.ps1" @($case.Args) 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$prior};if(($code -eq 0) -ne ($case.Code -eq 0) -or ($output -join "`n") -notmatch $case.Pattern){throw "CLI failed: $($case.Args -join ' ') -> $code / $($output -join ' ')"};$count++}
Write-Host "PASS: $count scoped PowerShell logging CLI guards."
exit 0
