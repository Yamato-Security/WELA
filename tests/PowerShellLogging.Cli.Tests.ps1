$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent;$engine=(Get-Process -Id $PID).Path;$count=0
$parameterAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'WELA.ps1'),[ref]$null,[ref]$null).ParamBlock.Parameters
$names=@($parameterAst|ForEach-Object {$_.Name.VariablePath.UserPath});$helpIndex=[array]::IndexOf($names,'Help')
foreach($name in @('PowerShellLoggingAction','PowerShellLoggingControl','PowerShellLoggingModuleName')){if([array]::IndexOf($names,$name) -le $helpIndex){throw 'New logging parameters must follow existing Help to preserve legacy positional binding.'};$count++}
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
foreach($case in $cases){
 # ProcessStartInfo preserves literal wildcard arguments on Unix PowerShell hosts too.
 $arguments=@('-NoLogo','-NoProfile','-NonInteractive','-File',"$repo/WELA.ps1")+@($case.Args)
 foreach($argument in $arguments){if($argument.Contains('"') -or $argument.EndsWith('\')){throw 'Ambiguous fixture argument.'}}
 $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$engine;$info.Arguments=(@($arguments|ForEach-Object{'"'+$_+'"'}) -join ' ');$info.UseShellExecute=$false;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
 $process=[Diagnostics.Process]::new();$process.StartInfo=$info;$started=$false
 try{if(-not $process.Start()){throw 'CLI child did not start.'};$started=$true;$stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync();if(-not $process.WaitForExit(30000)){throw 'CLI child timeout.'};$code=$process.ExitCode;$output=$stdout.Result+"`n"+$stderr.Result}
 finally{if($started -and -not $process.HasExited){$process.Kill();$process.WaitForExit()};$process.Dispose()}
 if(($code -eq 0) -ne ($case.Code -eq 0) -or $output -notmatch $case.Pattern){throw "CLI failed: $($case.Args -join ' ') -> $code / $output"};$count++
}
Write-Host "PASS: $count scoped PowerShell logging CLI guards."
exit 0
