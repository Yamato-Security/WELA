$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent;$engine=(Get-Process -Id $PID).Path
$cases=@(
 @{Args=@('wmi-auditing','-Help');Exit=0;Pattern='WmiIncludeChildren'},
 @{Args=@('wmi-auditing','-WmiAction','Plan','-WmiNamespace','root\default','-WmiIncludeChildren','-Help');Exit=0;Pattern='Usage:'},
 @{Args=@('wmi-auditing','-WmiAction','Configure','-WmiIncludeChildren','-DryRun','-Help');Exit=0;Pattern='Usage:'},
 @{Args=@('wmi-auditing','-WmiAction','Audit','-WmiIncludeChildren','-DryRun','-Help');Exit=1;Pattern='DryRun'},
 @{Args=@('configure','-WmiIncludeChildren','-Help');Exit=1;Pattern='require wmi-auditing'},
 @{Args=@('wmi-auditing','unexpected','-WmiIncludeChildren','-Help');Exit=1;Pattern='positional|argument|Unrecognized'},
 @{Args=@('wmi-auditing','-WmiNamespace','root\default','-FileProbeAction','Run','-Help');Exit=1;Pattern='require file-access-probe|dedicated'}
)
foreach($c in $cases){
 $ErrorActionPreference='Continue';try{$text=@(& $engine -NoProfile -File (Join-Path $repo 'WELA.ps1') @($c.Args) 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference='Stop'}
 if($code -ne $c.Exit -or ($text -join "`n") -notmatch $c.Pattern){throw "CLI mismatch: $($c.Args -join ' ') : $code / $text"}
}
Write-Host "PASS: $($cases.Count) WMI inheritance public CLI assertions."
$global:LASTEXITCODE=0
