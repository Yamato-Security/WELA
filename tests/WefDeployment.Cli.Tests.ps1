$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$shell=(Get-Process -Id $PID).Path
$script:count=0
function Assert-Cli([string[]]$Arguments,[int]$ExitCode,[string]$Text) {
    $ErrorActionPreference='Continue' # Native stderr in Windows PowerShell 5.1.
    $output=(& $shell -NoProfile -File (Join-Path $repo 'WELA.ps1') @Arguments 2>&1 | Out-String)
    $actual=$LASTEXITCODE
    $ErrorActionPreference='Stop'
    if ($actual -ne $ExitCode -or $output -notmatch [regex]::Escape($Text)) { throw "CLI regression ($actual, wanted $ExitCode): $($Arguments -join ' ')`n$output" }
    $script:count++
}
Assert-Cli @('wef-source','-Help') 0 'wef-source|wec-collector'
Assert-Cli @('wec-collector','-Help') 0 'existing'
Assert-Cli @('configure','-WefAction','Plan') 1 'require wef-source'
Assert-Cli @('version','-WefConfigPath','operator.json') 1 'require wef-source'
Assert-Cli @('wef-source','-WefAction','Audit','-DryRun') 1 'DryRun is supported only'
Assert-Cli @('wec-collector','-Profile','wela') 1 'own explicit JSON'
Assert-Cli @('wef-source','-HtmlPath','file.html') 1 'own explicit JSON'
Assert-Cli @('wec-collector','-LogProfile','ASD') 1 'LogProfile is supported only'
Assert-Cli @('wef-source','-ChannelAction','Configure') 1 'Channel options require'
Assert-Cli @('wef-source') 1 'WefConfigPath is required'
Write-Host "WefDeployment.Cli.Tests: $script:count public CLI checks passed."
