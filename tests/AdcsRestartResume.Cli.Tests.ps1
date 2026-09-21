$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent;$engine=(Get-Process -Id $PID).Path
$cases=@(
    @{Args=@('adcs-resume','-Help');Exit=0;Pattern='Usage:'},
    @{Args=@('adcs-resume','-AdcsResumeAction','Resume','-DryRun','-Help');Exit=0;Pattern='Usage:'},
    @{Args=@('adcs-auditing','-AdcsAction','Configure','-DryRun','-Help');Exit=0;Pattern='Usage:'},
    @{Args=@('adcs-resume','-Auto','-Help');Exit=1;Pattern='dedicated options'},
    @{Args=@('adcs-resume','-AllowRestart','-Help');Exit=1;Pattern='dedicated options'},
    @{Args=@('configure','-AdcsResumeAllowRestart','-Help');Exit=1;Pattern='require adcs-resume'},
    @{Args=@('adcs-auditing','-AdcsResumePlanPath','unread.json','-Help');Exit=1;Pattern='require adcs-resume'},
    @{Args=@('adcs-resume','-DryRun','-Help');Exit=1;Pattern='DryRun'},
    @{Args=@('adcs-resume','-Role','ADCS','-Help');Exit=1;Pattern='dedicated options'}
)
foreach($case in $cases){
    $ErrorActionPreference='Continue';try{$text=@(& $engine -NoProfile -File "$repo/WELA.ps1" @($case.Args) 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference='Stop'}
    if($code -ne $case.Exit -or ($text -join "`n") -notmatch $case.Pattern){throw "Unexpected CLI result for $($case.Args -join ' '): $code / $text"}
}
Write-Host "AD CS resume public CLI: $($cases.Count) checks passed."
$global:LASTEXITCODE=0
