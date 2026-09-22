$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$engine=(Get-Process -Id $PID).Path
$cases=@(
    @{Args=@('transcription-recovery','-Help');Code=0;Pattern='Usage: transcription-recovery'},
    @{Args=@('transcription-recovery','-TranscriptRecoveryAction','Restore','-Help');Code=0;Pattern='TranscriptRecoveryPlanHash'},
    @{Args=@('transcription-recovery','-Profile','CisV4L2');Code=1;Pattern='dedicated options'},
    @{Args=@('help','-TranscriptRecoveryAction','Plan');Code=1;Pattern='require transcription-recovery'},
    @{Args=@('transcription-recovery','-TranscriptRecoveryAction','Restore','-TranscriptRecoveryPlanHash','bad');Code=1;Pattern='Restore consumes'},
    @{Args=@('transcription-recovery','-Auto');Code=1;Pattern='Plan takes'},
    @{Args=@('transcription-recovery','-TranscriptRecoveryAllowTemporarySuspension');Code=1;Pattern='Plan takes'},
    @{Args=@('transcription-recovery','-TranscriptRecoveryAction','Restore','-WhatIf');Code=1;Pattern='dedicated options'},
    @{Args=@('transcription-recovery','-TranscriptRecoveryAction','Restore','-DryRnu');Code=1;Pattern='dedicated options'}
)
foreach($case in $cases) {
    $prior=$ErrorActionPreference
    try{$ErrorActionPreference='Continue';$output=@(& $engine -NoLogo -NoProfile -NonInteractive -File (Join-Path $repo 'WELA.ps1') @($case.Args) 2>&1);$code=$LASTEXITCODE}
    finally{$ErrorActionPreference=$prior}
    if($code -ne $case.Code -or ($output -join "`n") -notmatch $case.Pattern){throw "CLI failure: $($case.Args -join ' ') -> $code / $($output -join ' ')"}
}
Write-Host "Passed $($cases.Count) public transcription recovery CLI checks."
# Expected child refusals must not become the enclosing Actions step result.
$global:LASTEXITCODE=0
