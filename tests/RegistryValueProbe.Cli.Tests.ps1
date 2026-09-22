$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent;$engine=(Get-Process -Id $PID).Path;$count=0
$cases=@(
 @{Args=@('registry-probe','-Help');Pattern='existing current-user';Ok=$true},
 @{Args=@('configure','-RegistryProbeAction','Run');Pattern='RegistryProbe options require';Ok=$false},
 @{Args=@('registry-probe','-Auto');Pattern='dedicated options';Ok=$false},
 @{Args=@('registry-probe','-DryRun');Pattern='dedicated options';Ok=$false},
 @{Args=@('registry-probe','-Role','Client');Pattern='dedicated options';Ok=$false},
 @{Args=@('registry-probe','-Profile','wela-2.2.0');Pattern='dedicated options';Ok=$false},
 @{Args=@('registry-probe','-RegistryProbeAction','Run','-Typo');Pattern='Unsupported trailing';Ok=$false},
 @{Args=@('registry-probe','extra');Pattern='dedicated options';Ok=$false},
 @{Args=@('registry-probe','-RegistryProbeAction','Run');Pattern='Run requires';Ok=$false},
 @{Args=@('registry-probe','-RegistryProbeOutputPath','unused');Pattern='Run requires';Ok=$false}
)
foreach($case in $cases){$old=$ErrorActionPreference;try{$ErrorActionPreference='Continue';$output=@(&$engine -NoLogo -NoProfile -NonInteractive -File "$repo/WELA.ps1" @($case.Args) 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$old};if(($code -eq 0) -ne $case.Ok -or ($output -join ' ') -notmatch $case.Pattern){throw "CLI failed: $($case.Args) : $code $output"};$count++}
Write-Host "PASS: $count registry probe CLI guards."
