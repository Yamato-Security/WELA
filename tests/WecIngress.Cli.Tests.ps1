$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent
$engine=(Get-Process -Id $PID).Path;$count=0
$cases=@(
 @{Args=@('wec-ingress','-Help');Code=0;Pattern='TCP5985'},
 @{Args=@('configure','-WecIngressAction','Apply','-Auto');Code=1;Pattern='require wec-ingress'},
 @{Args=@('wec-ingress','-Help','-Profile','wela-2.2.0');Code=1;Pattern='only dedicated'},
 @{Args=@('wec-ingress','-Help','-WefAction','Configure');Code=1;Pattern='only dedicated'},
 @{Args=@('wec-ingress','-Help','-Auto');Code=1;Pattern='only dedicated'},
 @{Args=@('wec-ingress','-Help','-DryRun');Code=1;Pattern='only dedicated'},
 @{Args=@('wec-ingress','-WecIngressAction','Apply','-WecIngressOutputPath','not-created');Code=1;Pattern='reviewed plan'},
 @{Args=@('wec-ingress','-WecIngressOutputPath','not-created');Code=1;Pattern='Plan requires'}
)
foreach($case in $cases){$prior=$ErrorActionPreference;try{$ErrorActionPreference='Continue';$output=@(&$engine -NoLogo -NoProfile -NonInteractive -File "$repo/WELA.ps1" @($case.Args) 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$prior};if(($case.Code -eq 0 -and $code -ne 0) -or ($case.Code -ne 0 -and $code -eq 0) -or ($output -join "`n") -notmatch $case.Pattern){throw "CLI failure: $($case.Args -join ' ') -> $code / $($output -join ' ')"};$count++}
Write-Host "WEC ingress CLI: $count checks passed."
$global:LASTEXITCODE=0
