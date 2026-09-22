$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent;$engine=(Get-Process -Id $PID).Path
$cases=@(
    @{Args=@('registry-sacl-recovery','-Help');Code=0;Pattern='One proven registry-root audit ACE'},
    @{Args=@('registry-sacl-recovery','unexpected','-Help');Code=1;Pattern='arguments|dedicated options'},
    @{Args=@('registry-sacl-recovery','-WhatIf','-Help');Code=1;Pattern='arguments|dedicated options'},
    @{Args=@('registry-sacl-recovery','-DryRun','-Help');Code=1;Pattern='dedicated options'},
    @{Args=@('registry-sacl-recovery','-Auto','-Help');Code=1;Pattern='dedicated options'},
    @{Args=@('help','-RegistryRecoveryAction','Restore');Code=1;Pattern='require registry-sacl-recovery'},
    @{Args=@('registry-sacl-recovery');Code=1;Pattern='four original evidence paths'},
    @{Args=@('registry-sacl-recovery','-RegistryRecoveryAction','Restore');Code=1;Pattern='reviewed plan path/hash'},
    @{Args=@('registry-sacl-recovery','-RegistryRecoveryAllowAuditReduction');Code=1;Pattern='four original evidence paths'}
)
foreach($case in $cases){$old=$ErrorActionPreference;try{$ErrorActionPreference='Continue';$output=@(& $engine -NoLogo -NoProfile -NonInteractive -File (Join-Path $repo 'WELA.ps1') @($case.Args) 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$old};if($code -ne $case.Code -or ($output -join "`n") -notmatch $case.Pattern){throw "CLI refusal failure: $($case.Args -join ' ') => $code / $($output -join ' ')"}}
Write-Host "Passed $($cases.Count) public registry recovery CLI assertions.";$global:LASTEXITCODE=0
