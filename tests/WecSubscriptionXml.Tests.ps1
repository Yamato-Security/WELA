$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent
Import-Module "$repo/modules/WefSubscriptions.psm1" -Force
if(-not ('Wela.WecXml.Reader' -as [type])){
 $compile=@{Path="$repo/modules/WecSubscriptionXml.cs";ErrorAction='Stop'}
 if($PSVersionTable.PSEdition -eq 'Desktop'){$compile.ReferencedAssemblies=@('System.dll','System.Core.dll','System.Xml.dll')}
 Add-Type @compile
}
$count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Reject([scriptblock]$Action){$failed=$false;try{&$Action|Out-Null}catch{$failed=$true};Assert $failed 'Invalid native XML bytes/identity must fail'}
$text='<Subscription><Description>'+([string][char]0x65e5)+([string][char]0x672c)+([string][char]0x8a9e)+'</Description></Subscription>'
$bytes=[Text.Encoding]::Unicode.GetBytes($text)
foreach($value in @($bytes,([byte[]](@(255,254)+$bytes)),([Text.Encoding]::UTF8.GetBytes($text)),([byte[]](@(239,187,191)+[Text.Encoding]::UTF8.GetBytes($text))),([byte[]](@(254,255)+[Text.Encoding]::BigEndianUnicode.GetBytes($text))))){$decoded=[Wela.WecXml.Reader]::DecodeXml($value);Assert ($decoded -ceq $text) 'Strict UTF8/UTF16 with/without BOM preserves non-ASCII';Assert ((Read-WelaWefXml $decoded).DocumentElement.InnerText -ceq (([string][char]0x65e5)+([string][char]0x672c)+([string][char]0x8a9e))) 'Native XML is readable without console transcoding'}
Reject {[Wela.WecXml.Reader]::DecodeXml([byte[]]@())}
Reject {[Wela.WecXml.Reader]::DecodeXml([byte[]]@(60))}
Reject {[Wela.WecXml.Reader]::DecodeXml([byte[]]@(0,216))}
Reject {[Wela.WecXml.Reader]::DecodeXml([byte[]]@(60,120,62,195,40,60,47,120,62))}
Reject {[Wela.WecXml.Reader]::DecodeXml([Text.Encoding]::UTF8.GetBytes('<!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><x>&a;</x>'))}
Reject {[Wela.WecXml.Reader]::DecodeXml([Text.Encoding]::Unicode.GetBytes('native error'))}
Reject {[Wela.WecXml.Reader]::DecodeXml([byte[]]::new(10485762))}
foreach($id in @('bad"argument','bad\path',"bad`n")){Reject {[Wela.WecXml.Reader]::ReadXml($id)}}
Write-Host "WEC Unicode XML: $count assertions passed."
