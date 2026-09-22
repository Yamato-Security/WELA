$ErrorActionPreference='Stop';$root=Split-Path $PSScriptRoot -Parent;$engine=(Get-Process -Id $PID).Path;$count=0
$cases=@(
 @{Args=@('dns-client-probe','-Help');Code=0;Pattern='Fixed benign A lookup'},
 @{Args=@('configure','-DnsClientProbeAction','Run','-Auto');Code=1;Pattern='require dns-client-probe'},
 @{Args=@('dns-analytical','-DnsClientProbeResolver','127.0.0.1');Code=1;Pattern='only dedicated'},
 @{Args=@('dns-client-probe','-Help','-Auto');Code=1;Pattern='only dedicated'},
 @{Args=@('dns-client-probe','-Help','-DryRun');Code=1;Pattern='only dedicated'},
 @{Args=@('dns-client-probe','-Help','-WmiProbeAction','Run');Code=1;Pattern='only dedicated'},
 @{Args=@('dns-client-probe','-Help','-Profile','wela-2.2.0');Code=1;Pattern='only dedicated'},
 @{Args=@('dns-client-probe','-DnsClientProbeResolver','example.com');Code=1;Pattern='canonical unicast IPv4'},
 @{Args=@('dns-client-probe','-DnsClientProbeResolver','127.0.0.1','-DnsClientProbeAction','Run');Code=1;Pattern='Run requires a new output'},
 @{Args=@('dns-client-probe','-DnsClientProbeResolver','127.0.0.1','-DnsClientProbeOutputPath','unused');Code=1;Pattern='Plan writes no files'})
foreach($case in $cases){$ErrorActionPreference='Continue';$out=& $engine -NoLogo -NoProfile -NonInteractive -File (Join-Path $root 'WELA.ps1') @($case.Args) 2>&1|Out-String;$code=$LASTEXITCODE;$ErrorActionPreference='Stop';if($code -ne $case.Code -or $out -notmatch $case.Pattern){throw "Public CLI failed: $($case.Args -join ' ') [$code] $out"};$count++}
Write-Host "PASS: $count DNS Client public CLI checks.";$global:LASTEXITCODE=0
