# Exercise the real CLI as noninteractive child processes. No tenant is contacted.
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$shell=(Get-Process -Id $PID).Path;$script:checks=0
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-intune-cli-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
function Assert-Cli([string[]]$Arguments,[int]$Expected,[string]$Text) {
    $ErrorActionPreference='Continue'
    try { $output=& $shell -NoProfile -NonInteractive -File (Join-Path $repo 'WELA.ps1') @Arguments 2>&1;$code=$LASTEXITCODE } finally { $ErrorActionPreference='Stop' }
    if ($code -ne $Expected -or ($output -join "`n") -notmatch [regex]::Escape($Text)) { throw "CLI mismatch for $($Arguments -join ' '): exit=$code`n$($output -join "`n")" }
    $script:checks++
}
try {
    Assert-Cli @('intune-export','-Help') 0 'Offline native audit artifacts only'
    Assert-Cli @('intune-export') 1 'are required'
    foreach ($option in @('IntuneProfile','IntuneBuild','IntuneEdition','IntuneOutputPath','IntuneMinimumMode')) {
        $value=switch($option) {'IntuneBuild' {'26100'} 'IntuneMinimumMode' {'Reject'} default {'fixture'}}
        Assert-Cli @('configure','-Profile','wela-2.2.0',('-'+$option),$value) 1 'Intune options require'
    }
    foreach ($option in @('Auto','DryRun','GrantEventLogReaders','AllowPrivilegeRemoval')) { Assert-Cli @('intune-export',('-'+$option)) 1 'accepts only Intune' }
    foreach ($pair in @(@('Role','DomainController'),@('Profile','wela-2.2.0'),@('ResultsPath','report.json'),@('WefAction','Configure'))) { Assert-Cli @('intune-export',('-'+$pair[0]),$pair[1]) 1 'accepts only Intune' }
    $output=Join-Path $temp 'bundle'
    $arguments=@('intune-export','-IntuneProfile','microsoft-sct-win11-25h2','-IntuneBuild','26200','-IntuneEdition','Enterprise','-IntuneOutputPath',$output)
    Assert-Cli $arguments 0 'PreparedOffline'
    $receipt=Get-Content (Join-Path $output 'SHA256SUMS.json') -Raw -Encoding UTF8|ConvertFrom-Json
    if (-not $receipt.BundleComplete -or $receipt.Files.Count -ne 4) { throw 'Public CLI did not create a complete offline bundle.' };$script:checks++
    Assert-Cli $arguments 1 'already exists'
    Assert-Cli @('intune-export','-IntuneProfile','microsoft-wef-reviewed-2026-09','-IntuneBuild','26100','-IntuneEdition','Enterprise','-IntuneOutputPath',(Join-Path $temp 'blocked')) 1 'BlockedReviewOnly'
    if (Test-Path (Join-Path $temp 'blocked/graph-body.json')) { throw 'Blocked CLI produced a deployable body.' };$script:checks++
    Assert-Cli @('intune-export','-IntuneProfile','wela-2.2.0','-IntuneBuild','20348','-IntuneEdition','Enterprise','-IntuneOutputPath',(Join-Path $temp 'server')) 1 'builds 26100 and 26200'
    if (Test-Path (Join-Path $temp 'server')) { throw 'Invalid target created an output directory.' };$script:checks++
    Write-Host "PASS: $script:checks noninteractive Intune CLI assertions. No tenant or Windows policy changes."
} finally { Remove-Item -LiteralPath $temp -Recurse -Force }
$global:LASTEXITCODE=0
