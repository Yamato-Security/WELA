$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent
Import-Module "$repo/modules/WefSubscriptions.psm1" -Force
& (Get-Module WefSubscriptions) {Initialize-WelaWecSubscriptionInventory}
$count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Reject([scriptblock]$Action){$failed=$false;try{&$Action|Out-Null}catch{$failed=$true};Assert $failed 'Malformed, duplicate, partial or oversized native inventory must be rejected'}
Assert ([Wela.WecInventory.Reader]::SourceSha256 -ceq (Get-FileHash "$repo/modules/WecSubscriptionInventory.cs").Hash.ToLowerInvariant()) 'Loaded inventory binds exact source bytes'
Assert ([Wela.WecInventory.Reader]::ValidateNames([string[]]@()).Length -eq 0) 'Completed empty inventory is distinct from an error'
$unicode='Name '+[char]0x65e5+[char]0x672c
$names=[string[]]@('z',$unicode,'A',' leading ',([string][char]0xfeff))
$observed=[Wela.WecInventory.Reader]::ValidateNames($names)
Assert ($observed.Length -eq 5 -and $observed -ccontains $unicode -and $observed -ccontains ' leading ' -and $observed -ccontains ([string][char]0xfeff)) 'Actual Unicode and whitespace names are retained, never console-trimmed'
Assert ($names[0] -ceq 'z') 'Validation does not mutate caller inventory'
Reject {[Wela.WecInventory.Reader]::ValidateNames($null)}
Reject {[Wela.WecInventory.Reader]::ValidateNames([string[]]@('same','SAME'))}
Reject {[Wela.WecInventory.Reader]::ValidateNames([string[]]@(''))}
Reject {[Wela.WecInventory.Reader]::ValidateNames([string[]]@("ab`0cd"))}
Reject {[Wela.WecInventory.Reader]::ValidateNames([string[]]@('x'*1024))}
Reject {[Wela.WecInventory.Reader]::ValidateNames([string[]]@([string][char]0xd800))}
Reject {[Wela.WecInventory.Reader]::ValidateNames([string[]]@(1..4097|ForEach-Object {"id-$_"}))}
Reject {[Wela.WecInventory.Reader]::ValidateNames([string[]]@(1..1025|ForEach-Object {$prefix=[string]$_;$prefix+('x'*(1023-$prefix.Length))}))}
$buffer=[Runtime.InteropServices.Marshal]::AllocHGlobal(64)
try {
 for($i=0;$i -lt 64;$i++){[Runtime.InteropServices.Marshal]::WriteByte($buffer,$i,0)}
 $bytes=[Text.Encoding]::Unicode.GetBytes($unicode+[char]0);[Runtime.InteropServices.Marshal]::Copy($bytes,0,$buffer,$bytes.Length)
 Assert ([Wela.WecInventory.Reader]::DecodeName($buffer,($unicode.Length+1),32) -ceq $unicode) 'Native used length counts UTF16 characters including terminator'
 foreach($used in @(0,1,33)){Reject {[Wela.WecInventory.Reader]::DecodeName($buffer,$used,32)}}
 Reject {[Wela.WecInventory.Reader]::DecodeName([IntPtr]::Zero,2,32)}
 Reject {[Wela.WecInventory.Reader]::DecodeName($buffer,2,1025)}
 Reject {[Wela.WecInventory.Reader]::DecodeName($buffer,$unicode.Length,32)}
 [Runtime.InteropServices.Marshal]::WriteInt16($buffer,2,0);Reject {[Wela.WecInventory.Reader]::DecodeName($buffer,($unicode.Length+1),32)}
 [Runtime.InteropServices.Marshal]::WriteInt16($buffer,0,[int16]-10240);Reject {[Wela.WecInventory.Reader]::DecodeName($buffer,2,32)}
}finally{[Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)}
Write-Host "PASS: $count native subscription inventory buffer/boundary assertions."
