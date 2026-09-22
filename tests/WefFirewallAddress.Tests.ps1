# Scope comparison only; no firewall or Windows setting mutation.
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
Import-Module "$repo/modules/WefSubscriptions.psm1" -Force
$count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Reject([scriptblock]$Code){$caught=$false;try{&$Code|Out-Null}catch{$caught=$true};Assert $caught 'Malformed, broad or non-IP observed scope must be refused.'}
foreach($pair in @(
 @('192.0.2.0/24','192.0.2.0/255.255.255.0'),
 @('10.0.0.0/8','10.0.0.0/255.0.0.0'),
 @('192.0.2.1','192.0.2.1/255.255.255.255'),
 @('192.0.2.1/32','192.0.2.1'),
 @('192.0.2.128/25','192.0.2.128/255.255.255.128'),
 @('192.0.2.129/25','192.0.2.128/255.255.255.128'),
 @('2001:0DB8:0000:0000::/64','2001:db8::/64'),
 @('2001:db8::1/128','2001:0db8::1'),
 @('2001:db8::1/64','2001:db8::/64'),
 @('fe80::1%3','fe80:0:0:0:0:0:0:1%3')
)){
 Assert (Test-WelaWefFirewallAddressSet @($pair[0]) @($pair[1])) ('Equivalent scopes compare equal: '+($pair -join ' / '))
}
foreach($pair in @(
 @('192.0.2.0/24','192.0.2.0/255.255.254.0'),
 @('192.0.2.0/24','192.0.2.0/255.255.255.128'),
 @('192.0.2.0/24','198.51.100.0/255.255.255.0'),
 @('192.0.2.1','192.0.2.2'),
 @('2001:db8::/64','2001:db8::/63'),
 @('2001:db8::/64','2001:db8:0:1::/64'),
 @('192.0.2.1','::ffff:192.0.2.1'),
 @('fe80::1%3','fe80::1%4')
)){
 Assert (-not(Test-WelaWefFirewallAddressSet @($pair[0]) @($pair[1]))) ('Different scope is refused: '+($pair -join ' / '))
}
Assert (Test-WelaWefFirewallAddressSet @('2001:db8::/64','192.0.2.0/24') @('192.0.2.0/255.255.255.0','2001:0db8::/64')) 'Unordered mixed IPv4/IPv6 scopes remain equivalent.'
Assert (-not(Test-WelaWefFirewallAddressSet @('192.0.2.1') @('192.0.2.1','192.0.2.2'))) 'Extra native scope is not a match.'
Assert (-not(Test-WelaWefFirewallAddressSet @('192.0.2.1','192.0.2.2') @('192.0.2.1'))) 'Missing native scope is not a match.'
Assert (-not(Test-WelaWefFirewallAddressSet @('192.0.2.1') @())) 'Empty native scope is unknown, never Any.'
foreach($value in @('Any','LocalSubnet','example.org','192.0.2.1-192.0.2.10','192.0.2.0/0','192.0.2.0/0.0.0.0','192.0.2.0/255.0.255.0','192.0.2.0/255.255.999.0','192.0.2.0/255.255.0','192.0.2.0/33','::/0','::1/129','2001:db8::/255.255.255.0','192.0.2.1/24/32','')){Reject {Test-WelaWefFirewallAddressSet @('192.0.2.0/24') @($value)}}
Reject {Test-WelaWefFirewallAddressSet @('192.0.2.0/255.255.255.0') @('192.0.2.0/24')}
Reject {Test-WelaWefFirewallAddressSet @(1) @('192.0.2.1')}
Reject {Test-WelaWefFirewallAddressSet @('192.0.2.1') @(1)}
Write-Host "WEF firewall address comparison: $count assertions passed."
