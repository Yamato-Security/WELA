$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent;$engine=(Get-Process -Id $PID).Path;$count=0
$cases=@(
 @{Args=@('capi2-probe','-Help');Code=0;Pattern='Fixed offline'},
 @{Args=@('configure','-Capi2ProbeAction','Run','-Auto');Code=1;Pattern='require capi2-probe'},
 @{Args=@('wmi-auditing','-Capi2ProbeAction','Run');Code=1;Pattern='require capi2-probe'},
 @{Args=@('capi2-probe','-Help','-WmiAction','Configure');Code=1;Pattern='only dedicated'},
 @{Args=@('capi2-probe','-Help','-Auto');Code=1;Pattern='only dedicated'},
 @{Args=@('capi2-probe','-Help','-DryRun');Code=1;Pattern='only dedicated'},
 @{Args=@('capi2-probe','-Help','-ResultsPath','unused');Code=1;Pattern='only dedicated'},
 @{Args=@('capi2-probe','-Help','-Profile','wela-2.2.0');Code=1;Pattern='only dedicated'},
 @{Args=@('capi2-probe','-Capi2ProbeAction','Run');Code=1;Pattern='new Capi2ProbeOutputPath'})
foreach($case in $cases){$ErrorActionPreference='Continue';$output=& $engine -NoProfile -NonInteractive -File (Join-Path $repo 'WELA.ps1') @($case.Args) 2>&1|Out-String;$code=$LASTEXITCODE;$ErrorActionPreference='Stop';if($code -ne $case.Code -or $output -notmatch $case.Pattern){throw "CLI failed: $($case.Args -join ' ') [$code] $output"};$count++}
Write-Host "PASS: $count CAPI2 probe public CLI checks."
$global:LASTEXITCODE=0
