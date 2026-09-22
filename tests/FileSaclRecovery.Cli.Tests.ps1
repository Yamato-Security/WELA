$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent;$engine=(Get-Process -Id $PID).Path
$cases=@(
    @{Args=@('file-sacl-recovery','-Help');Exit=0;Pattern='Usage: file-sacl-recovery'},
    @{Args=@('file-sacl-recovery','-FileSaclRecoveryAction','Restore','-DryRun','-Help');Exit=0;Pattern='Usage:'},
    @{Args=@('file-sacl-recovery','-FileSaclRecoveryAction','Restore','-Auto','-Help');Exit=0;Pattern='Usage:'},
    @{Args=@('file-sacl-recovery','-DryRun','-Help');Exit=1;Pattern='DryRun'},
    @{Args=@('configure','-FileSaclRecoveryAction','Restore','-Help');Exit=1;Pattern='require file-sacl-recovery'},
    @{Args=@('targeted-sacl','-FileSaclRecoveryPlanPath','unread.json','-Help');Exit=1;Pattern='require file-sacl-recovery|targeted-sacl accepts only'},
    @{Args=@('file-sacl-recovery','-TargetSaclIncludeChildren','-Help');Exit=1;Pattern='require targeted-sacl|dedicated'},
    @{Args=@('file-sacl-recovery','-Role','Client','-Help');Exit=1;Pattern='dedicated'},
    @{Args=@('file-sacl-recovery','-ResultsPath','unwritten.json','-Help');Exit=1;Pattern='dedicated'},
    @{Args=@('file-sacl-recovery','-RecoveryPlanPath','unread.json','-Help');Exit=1;Pattern='dedicated'},
    @{Args=@('file-sacl-recovery','-Auto');Exit=1;Pattern='Plan requires four original'},
    @{Args=@('file-sacl-recovery','-FileSaclRecoveryAction','Restore','-Auto');Exit=1;Pattern='Restore requires PlanPath'},
    @{Args=@('file-sacl-recovery','-FileSaclRecoveryAction','Restore','-DryRun','-FileSaclRecoveryOutputPath','unwritten-directory');Exit=1;Pattern='Restore requires PlanPath'},
    @{Args=@('audit-recovery','-RecoveryAction','Restore','-DryRun','-Help');Exit=0;Pattern='Usage: audit-recovery'}
)
foreach($case in $cases){
    $ErrorActionPreference='Continue';try{$text=@(& $engine -NoProfile -File (Join-Path $repo 'WELA.ps1') @($case.Args) 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference='Stop'}
    if($code -ne $case.Exit -or ($text -join "`n") -notmatch $case.Pattern){throw "Unexpected CLI result for $($case.Args -join ' '): $code / $text"}
}
Write-Host "File SACL recovery public CLI: $($cases.Count) checks passed."
$global:LASTEXITCODE=0
