$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$engine=Join-Path $PSHOME $(if($PSEdition -eq 'Core'){if($env:OS -eq 'Windows_NT'){'pwsh.exe'}else{'pwsh'}}else{'powershell.exe'})
$count=0
function Check-Command([string]$Arguments,[int]$ExpectedExit,[string]$Pattern) {
 $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$engine;$info.Arguments='-NoProfile -File "'+(Join-Path $repo 'WELA.ps1')+'" '+$Arguments;$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
 $process=[Diagnostics.Process]::new();$process.StartInfo=$info;$started=$false
 try {
  $started=$process.Start();$out=$process.StandardOutput.ReadToEndAsync();$err=$process.StandardError.ReadToEndAsync()
  if(-not $process.WaitForExit(30000)){throw 'CLI timeout'}
  if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($out,$err),5000)){throw 'CLI output timeout'}
  $text=$out.GetAwaiter().GetResult()+$err.GetAwaiter().GetResult()
  if(($process.ExitCode -eq 0) -ne ($ExpectedExit -eq 0) -or $text -notmatch $Pattern){throw "CLI mismatch: $Arguments ; Exit=$($process.ExitCode) ; $text"};$script:count++
 }finally{if($started -and -not $process.HasExited){$process.Kill();$null=$process.WaitForExit(5000)};$process.Dispose()}
}
Check-Command 'applocker-script-probe -Help' 0 'existing Script AuditOnly'
Check-Command 'help' 0 'applocker-script-probe'
Check-Command 'version -AppLockerScriptAction Run' 1 'AppLockerScript options require'
Check-Command 'applocker-script-probe -AppLockerScriptAction Run -WhatIf' 1 'only its dedicated'
Check-Command 'applocker-script-probe -AppLockerScriptAction Run -DryRun' 1 'only its dedicated'
Check-Command 'applocker-script-probe -Auto' 1 'only its dedicated'
Check-Command 'applocker-script-probe -AppLockerProbeAction Run' 1 'only its dedicated'
Check-Command 'applocker-script-probe -AppLockerScriptAction Run' 1 'Run requires'
Check-Command 'applocker-script-probe -AppLockerScriptAction Plan -AppLockerScriptOutputPath ignored' 1 'Run requires'
Write-Host "AppLocker Script public CLI fixtures passed: $count checks."
