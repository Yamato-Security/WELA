$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent;$shell=(Get-Process -Id $PID).Path;$script:count=0
function Assert-Cli([string[]]$Arguments,[int]$ExitCode,[string]$Text){
 $ErrorActionPreference='Continue';$output=(& $shell -NoProfile -File (Join-Path $repo 'WELA.ps1') @Arguments 2>&1|Out-String);$actual=$LASTEXITCODE;$ErrorActionPreference='Stop'
 if($actual -ne $ExitCode -or $output -notmatch [regex]::Escape($Text)){throw "CLI regression ($actual expected $ExitCode): $($Arguments -join ' ')`n$output"};$script:count++
}
Assert-Cli @('wef-query','-Help') 0 'exact selected local QueryList'
Assert-Cli @('version','-WefQueryConfigPath','source.json') 1 'WefQuery options require'
Assert-Cli @('wef-query','-Auto') 1 'dedicated read-only options'
Assert-Cli @('wef-query','-DryRun') 1 'dedicated read-only options'
Assert-Cli @('wef-query','-WhatIf') 1 'dedicated read-only options'
Assert-Cli @('wef-query','-ResultsPath','out.json') 1 'dedicated read-only options'
Assert-Cli @('wef-query','-WefAction','Configure') 1 'dedicated read-only options'
Assert-Cli @('wef-query','-WefQueryMaximumEvents','0') 1 'less than the minimum'
Assert-Cli @('wef-query','-WefQueryMaximumEvents','65') 1 'greater than the maximum'
Assert-Cli @('wef-query') 1 'exact source config path and subscription ID'
Write-Host "WefQuery.Cli.Tests: $script:count public CLI checks passed."
$global:LASTEXITCODE=0
