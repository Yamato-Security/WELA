$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent;$engine=(Get-Process -Id $PID).Path;$count=0
$cases=@(
 @{Args=@('wmi-sacl-recovery','-Help');Code=0;Pattern='one proven parent-only'},
 @{Args=@('configure','-WmiRecoveryAction','Recover','-Auto');Code=1;Pattern='require wmi-sacl-recovery'},
 @{Args=@('wmi-sacl-recovery','-Help','-Auto');Code=1;Pattern='only dedicated'},
 @{Args=@('wmi-sacl-recovery','-Help','-DryRun');Code=1;Pattern='only dedicated'},
 @{Args=@('wmi-sacl-recovery','-Help','-WmiAction','Configure');Code=1;Pattern='only dedicated'},
 @{Args=@('wmi-sacl-recovery','-Help','-WmiIncludeChildren');Code=1;Pattern='only dedicated'},
 @{Args=@('wmi-sacl-recovery','-Help','-Profile','wela-2.2.0');Code=1;Pattern='only dedicated'},
 @{Args=@('wmi-sacl-recovery','-Help','-UnknownOption');Code=1;Pattern='Unsupported|Unexpected|unbound|only dedicated'},
 @{Args=@('wmi-sacl-recovery','extra');Code=1;Pattern='Unsupported|Unexpected|unbound|only dedicated'},
 @{Args=@('wmi-sacl-recovery');Code=1;Pattern='Plan requires'},
 @{Args=@('wmi-sacl-recovery','-WmiRecoveryAction','Recover','-WmiRecoveryPlanPath','absent','-WmiRecoveryPlanHash','bad');Code=1;Pattern='Recover requires'})
foreach($case in $cases){$ErrorActionPreference='Continue';$text=& $engine -NoLogo -NoProfile -NonInteractive -File "$repo/WELA.ps1" @($case.Args) 2>&1|Out-String;$code=$LASTEXITCODE;$ErrorActionPreference='Stop';if($code -ne $case.Code -or $text -notmatch $case.Pattern){throw "CLI boundary failed: $($case.Args -join ' ') [$code] $text"};$count++}
Write-Host "PASS: $count WMI SACL recovery public CLI guards.";$global:LASTEXITCODE=0
