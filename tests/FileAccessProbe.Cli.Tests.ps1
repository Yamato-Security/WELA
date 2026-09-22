$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent;$engine=(Get-Process -Id $PID).Path
$cases=@(
    @{Args=@('file-access-probe','-Help');Code=0;Pattern='Reads one byte and discards it'},
    @{Args=@('file-access-probe','-FileProbeAction','Run','-WhatIf');Code=1;Pattern='dedicated options'},
    @{Args=@('file-access-probe','extra','-Help');Code=1;Pattern='dedicated options'},
    @{Args=@('file-access-probe','-Auto','-Help');Code=1;Pattern='dedicated options'},
    @{Args=@('file-access-probe','-DryRun','-Help');Code=1;Pattern='dedicated options'},
    @{Args=@('help','-FileProbeAction','Run');Code=1;Pattern='require file-access-probe'},
    @{Args=@('file-access-probe','-FileProbePath','\\host\share\file');Code=1;Pattern='exact ordinary'},
    @{Args=@('file-access-probe','-FileProbePath','C:\file.txt','-FileProbeAction','Run');Code=1;Pattern='Run requires'},
    @{Args=@('file-access-probe','-FileProbePath','C:\file.txt','-FileProbeOutputPath','never-created');Code=1;Pattern='Plan creates no output'}
)
foreach($case in $cases){$old=$ErrorActionPreference;try{$ErrorActionPreference='Continue';$output=@(& $engine -NoLogo -NoProfile -NonInteractive -File (Join-Path $repo 'WELA.ps1') @($case.Args) 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$old};if($code -ne $case.Code -or ($output -join "`n") -notmatch $case.Pattern){throw "CLI refusal failure: $($case.Args -join ' ') => $code / $($output -join ' ')"}}
Write-Host "Passed $($cases.Count) public file-access CLI assertions.";$global:LASTEXITCODE=0
