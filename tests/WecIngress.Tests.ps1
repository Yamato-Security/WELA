$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
Import-Module "$repo/modules/AuditProfiles.psm1" -Force
. "$repo/scripts/WefArrival.ps1"
. "$repo/scripts/WecUpdate.ps1"
. "$repo/scripts/WecIngress.ps1"
$count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Reject([scriptblock]$Action,[string]$Pattern){$message='';try{&$Action|Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern; got $message"}
$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-ingress-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
$script:mode='ok';$script:reads=0;$script:creates=0;$script:exists=$false
function Get-WelaIngressContext {[pscustomobject][ordered]@{Computer='TEST';Addresses=@('10.10.10.10');Reader='LOGON'}}
function Assert-WelaIngressAbsent {param($Name);$script:reads++;if($script:exists -or ($script:mode -eq 'race' -and $script:reads -eq 2)){throw 'already exists'}}
function New-WelaIngressNativeRule {param($Selection);Assert (Test-Path $script:journal) 'Pending receipt precedes creation';$script:creates++;if($script:mode -eq 'failure'){throw 'native failure'};$script:exists=$true}
function Read-WelaIngressRule {
 param($Store,$Name)
 $r=[pscustomobject]@{Name=$Name;DisplayName=$Name;Description='WELA reviewed collector ingress; TCP 5985, Domain profile, explicit IPv4 scopes.';Group='WELA reviewed collector ingress';Enabled='True';Profile='Domain';Direction='Inbound';Action='Allow';EdgeTraversalPolicy='Block';LooseSourceMapping=$false;LocalOnlyMapping=$false;PolicyStoreSourceType='Local';Owner='';Platform=@()}
 $f=[ordered]@{Port=[pscustomobject]@{Protocol='TCP';LocalPort='5985';RemotePort='Any';IcmpType='Any';DynamicTarget='Any'};Address=[pscustomobject]@{LocalAddress=@('10.10.10.10');RemoteAddress=@('192.0.2.0/255.255.255.0')};Application=[pscustomobject]@{Program='Any';Package='Any'};Service=[pscustomobject]@{Service='Any'};Interface=[pscustomobject]@{InterfaceAlias='Any'};InterfaceType=[pscustomobject]@{InterfaceType='Any'};Security=[pscustomobject]@{Authentication='NotRequired';Encryption='NotRequired';OverrideBlockRules=$false;LocalUser='Any';RemoteUser='Any';RemoteMachine='Any'}}
 if($script:mode -eq 'broader'){$f.Address.RemoteAddress=@('Any')}
 if($script:mode -eq 'wrong-port'){$f.Port.LocalPort='Any'}
 if($script:mode -eq 'wrong-store' -and $Store -eq 'ActiveStore'){$r.PolicyStoreSourceType='GroupPolicy'}
 [pscustomobject]@{Store=$Store;Rule=$r;Filters=$f}
}
try {
 foreach($bad in @('Any','10.1','010.0.0.1','127.0.0.1','0.0.0.0','224.0.0.1','255.255.255.255','10.0.0.1/24','10.0.0.0/16','192.0.2.0/33','192.0.2.0/024','192.0.2.0/255.255.255.0','example.org','192.0.2.1-192.0.2.4','::1')){Reject {ConvertTo-WelaIngressAddress $bad -Remote} '.'}
 Assert ((ConvertTo-WelaIngressAddress '192.0.2.0/255.255.255.0' -Remote -Observed) -eq '192.0.2.0/24') 'Observed mask canonicalized'
 Reject {ConvertTo-WelaIngressAddress '192.0.2.0/255.0.255.0' -Remote -Observed} 'Noncontiguous'
 Reject {Get-WelaIngressSelection 'WELA-WEC-Test' @('10.10.10.10') @('192.0.2.1','192.0.2.1/32')} 'Duplicate'
 Reject {Get-WelaIngressSelection '*' @('10.10.10.10') @('192.0.2.1')} 'name'
 $selection=Get-WelaIngressSelection 'WELA-WEC-Test' @('10.10.10.10') @('192.0.2.0/24')
 $observation=Read-WelaIngressRule PersistentStore $selection.Name;Assert-WelaIngressReadback $observation $selection
 foreach($package in @($null,'')){$observation.Filters.Application.Package=$package;Assert-WelaIngressReadback $observation $selection;$count++}
 $observation.Filters.Application.Package='S-1-15-2-1';Reject {Assert-WelaIngressReadback $observation $selection} 'Package'
 $observation.Filters.Application.PSObject.Properties.Remove('Package');Reject {Assert-WelaIngressReadback $observation $selection} 'Package'
 $observation.Filters.Application|Add-Member NoteProperty Package 'Any'
 $evidence=ConvertTo-WelaIngressEvidence $observation;Assert ($evidence.Application.Package.Present -and $evidence.Application.Package.Value -eq 'Any') 'Evidence preserves explicit inspected fields'
 foreach($field in @('Enabled','Direction','Profile','Action','EdgeTraversalPolicy','LooseSourceMapping','LocalOnlyMapping','PolicyStoreSourceType','Description','Group','DisplayName','Name')){
   $saved=$observation.Rule.$field;$observation.Rule.$field='unexpected';Reject {Assert-WelaIngressReadback $observation $selection} 'differs';$observation.Rule.$field=$saved
 }
 foreach($scenario in @('ok','hash','context','duplicate','race','failure','broader','wrong-port','wrong-store','unassigned','replay')){
  $script:mode='ok';$script:reads=0;$script:creates=0;$script:exists=$false
  $result=Invoke-WelaWecIngress Plan -Name $selection.Name -LocalAddress $selection.LocalAddresses -RemoteAddress $selection.RemoteAddresses -OutputPath (Join-Path $root ($scenario+'-plan'))
  Assert ($result.Status -eq 'ReviewRequired' -and $script:creates -eq 0) "Read-only plan: $($result.Diagnostic)"
  $path=Join-Path $result.OutputPath 'plan.json';$hash=$result.PlanHash
  if($scenario -eq 'hash'){$hash='b'*64}
  if($scenario -in @('context','duplicate','unassigned')){
    $text=[IO.File]::ReadAllText($path)
    if($scenario -eq 'context'){$text=$text.Replace('TEST','OTHER')}
    if($scenario -eq 'duplicate'){$text=$text.Replace('"SchemaVersion":','"SchemaVersion":1,"SchemaVersion":')}
    if($scenario -eq 'unassigned'){$text=$text.Replace('"10.10.10.10"','"10.10.10.11"')}
    [IO.File]::WriteAllText($path,$text);$hash=(Get-FileHash $path).Hash.ToLowerInvariant()
  }
  $script:mode=$scenario;$script:reads=0;$out=Join-Path $root ($scenario+'-apply');$script:journal=Join-Path $out 'before-create.json'
  $applied=Invoke-WelaWecIngress Apply -PlanPath $path -PlanHash $hash -OutputPath $out
  Assert (($applied.ExitCode -eq 0) -eq ($scenario -in @('ok','replay'))) "Scenario $scenario : $($applied.Diagnostic)"
  Assert ($applied.ReadyRuleCredit -eq 0 -and (Test-Path (Join-Path $out 'manifest.json'))) 'No detection credit; durable result'
  if($scenario -in @('hash','context','duplicate','race','unassigned')){Assert ($script:creates -eq 0) 'Refused before mutation'}
  if($scenario -in @('failure','broader','wrong-port','wrong-store')){Assert ($applied.Status -eq 'CreateAttemptedUnverified' -and $script:creates -eq 1) 'Unverified possible creation retained'}
  if($scenario -eq 'replay'){$again=Invoke-WelaWecIngress Apply -PlanPath $path -PlanHash $hash -OutputPath (Join-Path $root 'replay-again');Assert ($again.Status -eq 'Refused' -and $script:creates -eq 1) 'Existing rule never overwritten'}
 }
}finally{Remove-Item $root -Recurse -Force}
Write-Host "WEC ingress tests passed: $count assertions."
