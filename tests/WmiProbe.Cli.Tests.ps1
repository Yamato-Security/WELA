$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent;$engine=(Get-Process -Id $PID).Path;$count=0
$cases=@(
 @{Args=@('wmi-probe','-Help');Code=0;Pattern='Fixed local read'},
 @{Args=@('configure','-WmiProbeAction','Run','-Auto');Code=1;Pattern='require wmi-probe'},
 @{Args=@('wmi-auditing','-WmiProbeNamespace','root\default');Code=1;Pattern='require wmi-probe'},
 @{Args=@('wmi-probe','-Help','-WmiAction','Configure');Code=1;Pattern='only dedicated'},
 @{Args=@('wmi-probe','-Help','-Auto');Code=1;Pattern='only dedicated'},
 @{Args=@('wmi-probe','-Help','-DryRun');Code=1;Pattern='only dedicated'},
 @{Args=@('wmi-probe','-Help','-ResultsPath','unused');Code=1;Pattern='only dedicated'},
 @{Args=@('wmi-probe','-Help','-Profile','wela-2.2.0');Code=1;Pattern='only dedicated'},
 @{Args=@('wmi-probe','-WmiProbeNamespace','\\remote\root\default');Code=1;Pattern='exact local'},
 @{Args=@('wmi-probe','-WmiProbeNamespace','root\default','-WmiProbeAction','Run');Code=1;Pattern='new WmiProbeOutputPath'})
foreach($case in $cases){$ErrorActionPreference='Continue';$output=& $engine -NoProfile -NonInteractive -File (Join-Path $repo 'WELA.ps1') @($case.Args) 2>&1|Out-String;$code=$LASTEXITCODE;$ErrorActionPreference='Stop';if($code -ne $case.Code -or $output -notmatch $case.Pattern){throw "CLI failed: $($case.Args -join ' ') [$code] $output"};$count++}
Write-Host "PASS: $count WMI probe public CLI checks."
$global:LASTEXITCODE=0
