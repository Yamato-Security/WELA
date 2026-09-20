# Child-process public dispatch regressions: no domain connection or policy writers.
$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent
$engine=(Get-Process -Id $PID).Path;$checks=0
$cases=@(
    @{Args=@('gpo-create','-Help');Code=0;Pattern='disabled, unlinked'},
    @{Args=@('configure','-GpoCreateAction','Create','-Auto');Code=1;Pattern='creation options require'},
    @{Args=@('gpo-create','-Help','-Profile','wela-2.2.0');Code=1;Pattern='only its dedicated'},
    @{Args=@('gpo-create','-Help','-GpoAction','Export');Code=1;Pattern='only its dedicated'},
    @{Args=@('gpo-create','-GpoCreateAction','Plan','-DryRun');Code=1;Pattern='DryRun is supported only'},
    @{Args=@('gpo-create','-GpoCreateAction','Create');Code=1;Pattern='explicit fresh'},
    @{Args=@('gpo-create','-GpoCreateAction','Review','-Auto');Code=1;Pattern='require GpoCreateAction'},
    @{Args=@('gpo-create','-GpoCreateAction','Review','-ResultsPath','should-not-exist.json');Code=1;Pattern='only its dedicated'}
)
foreach($case in $cases){
    $prior=$ErrorActionPreference
    try {$ErrorActionPreference='Continue';$output=@(& $engine -NoLogo -NoProfile -NonInteractive -File (Join-Path $repo 'WELA.ps1') @($case.Args) 2>&1);$code=$LASTEXITCODE}
    finally {$ErrorActionPreference=$prior}
    if(($case.Code -eq 0 -and $code -ne 0) -or ($case.Code -ne 0 -and $code -eq 0) -or ($output -join "`n") -notmatch $case.Pattern){throw "CLI failure: $($case.Args -join ' ') -> $code / $($output -join ' ')"};$checks++
}
Write-Host "GPO creation public CLI: $checks checks passed."
$global:LASTEXITCODE=0
