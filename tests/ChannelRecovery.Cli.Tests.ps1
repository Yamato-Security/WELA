$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent
$engine=(Get-Process -Id $PID).Path;$count=0
$cases=@(
 @{Args=@('channel-recovery','-ChannelRecoveryAction','Restore','-WhatIf');Code=1;Pattern='only dedicated|Unknown|unbound'},
 @{Args=@('channel-recovery','-Help');Code=0;Pattern='AllowShrink'},
 @{Args=@('configure','-ChannelRecoveryAction','Restore','-Auto');Code=1;Pattern='require channel-recovery'},
 @{Args=@('channel-recovery','-Help','-Profile','wela-2.2.0');Code=1;Pattern='only dedicated|Unknown|unbound'},
 @{Args=@('channel-recovery','-Help','-WefAction','Configure');Code=1;Pattern='only dedicated|Unknown|unbound'},
 @{Args=@('channel-recovery','-Help','-Auto');Code=1;Pattern='only dedicated|Unknown|unbound'},
 @{Args=@('channel-recovery','-Help','-DryRun');Code=1;Pattern='only dedicated|Unknown|unbound'},
 @{Args=@('channel-recovery','-ChannelRecoveryAction','Restore','-ChannelRecoveryOutputPath','not-created');Code=1;Pattern='reviewed plan'},
 @{Args=@('channel-recovery','-ChannelRecoveryOutputPath','not-created');Code=1;Pattern='Plan requires'}
)
foreach($case in $cases){$prior=$ErrorActionPreference;try{$ErrorActionPreference='Continue';$output=@(&$engine -NoLogo -NoProfile -NonInteractive -File "$repo/WELA.ps1" @($case.Args) 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$prior};if(($case.Code -eq 0 -and $code -ne 0) -or ($case.Code -ne 0 -and $code -eq 0) -or ($output -join "`n") -notmatch $case.Pattern){throw "CLI failure: $($case.Args -join ' ') -> $code / $($output -join ' ')"};$count++}
Write-Host "Channel recovery CLI: $count checks passed."
$global:LASTEXITCODE=0
