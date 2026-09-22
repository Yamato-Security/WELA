$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent;$engine=(Get-Process -Id $PID).Path;$count=0
$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-listener-cli-'+[guid]::NewGuid().ToString('N'))
$cases=@(
 @{Args=@('wec-listener','-Help');Code=0;Pattern='HTTP5985'},
 @{Args=@('wec-listener','-Help','-Auto');Code=1;Pattern='only dedicated'},
 @{Args=@('wec-listener','-Help','-DryRun');Code=1;Pattern='only dedicated'},
 @{Args=@('wec-listener','-WecListenerAction','Apply','-WhatIf');Code=1;Pattern='only dedicated'},
 @{Args=@('wec-listener','-Help','-Typo');Code=1;Pattern='only dedicated'},
 @{Args=@('wec-listener','-Help','-ResultsPath',$root);Code=1;Pattern='only dedicated'},
 @{Args=@('wec-listener','-Help','-WecIngressAction','Apply');Code=1;Pattern='only dedicated'},
 @{Args=@('configure','-WecListenerAction','Apply','-Auto');Code=1;Pattern='WecListener options require'},
 @{Args=@('wec-listener');Code=1;Pattern='Plan requires'},
 @{Args=@('wec-listener','-WecListenerComputerName','placeholder','-WecListenerLocalAddress','192.0.2.10','-WecListenerOutputPath',$root,'-WecListenerPlanPath','unused');Code=1;Pattern='Plan requires'},
 @{Args=@('wec-listener','-WecListenerAction','Apply','-WecListenerOutputPath',$root);Code=1;Pattern='Apply requires'},
 @{Args=@('wec-listener','-WecListenerAction','Apply','-WecListenerPlanPath','unused','-WecListenerPlanHash',('a'*64),'-WecListenerOutputPath',$root,'-WecListenerComputerName','placeholder');Code=1;Pattern='Apply requires'}
)
foreach($case in $cases){
 $prior=$ErrorActionPreference
 try{$ErrorActionPreference='Continue';$output=&$engine -NoLogo -NoProfile -NonInteractive -File "$repo/WELA.ps1" @($case.Args) 2>&1|Out-String;$code=$LASTEXITCODE}finally{$ErrorActionPreference=$prior}
 if($code -ne $case.Code -or $output -notmatch $case.Pattern){throw "CLI failed [$code]: $output"};$count++
 if(Test-Path -LiteralPath $root){throw 'Rejected CLI inputs must not create an output directory.'}
}
Write-Host "PASS: $count public WEC listener CLI checks. No Windows settings changed."
$global:LASTEXITCODE=0
