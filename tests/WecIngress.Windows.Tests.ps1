param([switch]$AllowDisposableFirewallRule)
$ErrorActionPreference='Stop'
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not $AllowDisposableFirewallRule -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Explicit disposable GitHub-hosted Windows opt-in required.'}
$repo=Split-Path $PSScriptRoot -Parent;$script:ScriptRoot=$repo
Import-Module "$repo/modules/AuditProfiles.psm1" -Force
Import-Module "$repo/modules/WefSubscriptions.psm1" -Force
. "$repo/scripts/WefDeployment.ps1"
. "$repo/scripts/WefArrival.ps1"
. "$repo/scripts/WecUpdate.ps1"
. "$repo/scripts/ChannelRead.ps1"
. "$repo/scripts/WecIngress.ps1"
$count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Key($Value){ConvertTo-Json -InputObject $Value -Depth 16 -Compress}
function RulesKey {param([string]$Exclude);Key @(Read-WelaIngressRules PersistentStore|Where-Object Name -ne $Exclude|Sort-Object Name|Select-Object Name,DisplayName,Description,Group,Enabled,Profile,Direction,Action,EdgeTraversalPolicy,LooseSourceMapping,LocalOnlyMapping,Owner)}
$engine=(Get-Process -Id $PID).Path
function Invoke-IngressFixtureCli {param([string[]]$Arguments,[int]$Expected=0)
 $old=$ErrorActionPreference;try{$ErrorActionPreference='Continue';$lines=@(&$engine -NoLogo -NoProfile -NonInteractive -File "$repo/WELA.ps1" @Arguments 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$old}
 if(($Expected -eq 0 -and $code -ne 0) -or ($Expected -ne 0 -and $code -eq 0)){throw "CLI $code : $($lines -join ' ')"}
}
$context=Get-WelaIngressContext;$contextKey=Key $context;$beforeRules=RulesKey ''
$local=@($context.Addresses|Where-Object {$_ -notlike '127.*' -and $_ -notlike '169.254.*'})[0]
if(-not $local){throw 'An assigned nonloopback IPv4 address is required.'}
$name='WELA-WEC-Test-'+[guid]::NewGuid().ToString('N');$selection=Get-WelaIngressSelection $name @($local) @('192.0.2.0/24')
$root=Join-Path $env:RUNNER_TEMP ('wela-ingress-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
$primary=$null;$attempted=$false
try {
 Assert-WelaIngressAbsent $name
 Invoke-IngressFixtureCli @('wec-ingress','-WecIngressName',$name,'-WecIngressLocalAddress',$local,'-WecIngressRemoteAddress','192.0.2.0/24','-WecIngressOutputPath',"$root/plan")
 $plan=Get-Content "$root/plan/manifest.json" -Raw|ConvertFrom-Json
 Assert ($plan.Status -eq 'ReviewRequired' -and -not $plan.NativeCreateAttempted) 'Public Plan is read only'
 Assert ((RulesKey '') -ceq $beforeRules) 'Planning preserves persistent rule inventory and properties'
 $attempted=$true
 Invoke-IngressFixtureCli @('wec-ingress','-WecIngressAction','Apply','-WecIngressPlanPath',"$root/plan/plan.json",'-WecIngressPlanHash',$plan.PlanHash,'-WecIngressOutputPath',"$root/apply")
 $apply=Get-Content "$root/apply/manifest.json" -Raw|ConvertFrom-Json
 Assert ($apply.Status -eq 'CreatedAndVerified' -and $apply.NativeCreateAttempted -and $apply.ReadyRuleCredit -eq 0) 'Actual public creation and readback'
 foreach($store in @('PersistentStore','ActiveStore')){Assert-WelaIngressReadback (Read-WelaIngressRule $store $name) $selection;$count++}
 Assert ((RulesKey $name) -ceq $beforeRules) 'Other persistent rule properties preserved'
 # Exercise the real existing collector prerequisite against the new native rule.
 # Other prerequisites may be unmet on this standalone fixture; inspect only ingress.
 $collectorConfig=[pscustomobject]@{CollectorFqdn=(Get-WelaWefHost).Fqdn;ListenerAddress='*';IngressRuleName=$name;IngressLocalAddresses=@($local);IngressRemoteAddresses=@('192.0.2.0/24')}
 $collectorChecks=@(Get-WelaWefCollectorPrerequisites $collectorConfig)
 $ingress=@($collectorChecks|Where-Object Name -eq 'Existing scoped domain ingress rule')
 Assert ($ingress.Count -eq 1 -and $ingress[0].Verified) 'Existing collector prerequisite accepts the same reviewed CIDR after native dotted-netmask readback'
 $null=Write-WelaWecUpdateArtifact $root 'collector-ingress-check.json' ($ingress[0]|ConvertTo-Json -Depth 8)
 $collectorConfig.IngressRemoteAddresses=@('192.0.2.0/25')
 $mismatch=@(Get-WelaWefCollectorPrerequisites $collectorConfig|Where-Object Name -eq 'Existing scoped domain ingress rule')
 Assert ($mismatch.Count -eq 1 -and -not $mismatch[0].Verified) 'Collector prerequisite refuses a genuinely different approved network'
 $null=Write-WelaWecUpdateArtifact $root 'collector-ingress-mismatch.json' ($mismatch[0]|ConvertTo-Json -Depth 8)
 # Native New must not replace an existing name, even if a creator races our last absence check.
 $collision=$false;try{New-WelaIngressNativeRule $selection}catch{$collision=$true}
 Assert $collision 'Native duplicate-name creation refuses replacement'
 Assert-WelaIngressReadback (Read-WelaIngressRule PersistentStore $name) $selection
 Invoke-IngressFixtureCli @('wec-ingress','-WecIngressAction','Apply','-WecIngressPlanPath',"$root/plan/plan.json",'-WecIngressPlanHash',$plan.PlanHash,'-WecIngressOutputPath',"$root/replay") 1
 $replay=Get-Content "$root/replay/manifest.json" -Raw|ConvertFrom-Json
 Assert ($replay.Status -eq 'Refused' -and -not $replay.NativeCreateAttempted) 'Plan replay refuses an existing rule'
 Assert ((Key (Get-WelaIngressContext)) -ceq $contextKey) 'Profiles, services, host and address context unchanged'
 Write-Host "Native WEC ingress passed $count assertions on $([Environment]::OSVersion.Version), PowerShell $($PSVersionTable.PSVersion). No listener or traffic created."
}catch{
 $primary=$_
 foreach($store in @('PersistentStore','ActiveStore')){try{$snapshot=ConvertTo-WelaIngressEvidence (Read-WelaIngressRule $store $name);Write-Host ($snapshot|ConvertTo-Json -Depth 8)}catch{Write-Host "Diagnostic read $store : $($_.Exception.Message)"}}
}
finally {
 $errors=@()
 try {
  $owned=@(Read-WelaIngressRules PersistentStore|Where-Object Name -eq $name)
  if($owned.Count){if(-not $attempted -or $owned.Count -ne 1 -or $owned[0].Group -cne 'WELA reviewed collector ingress' -or $owned[0].DisplayName -cne $name){throw 'Fixture ownership is ambiguous; refusing removal.'};$owned[0]|NetSecurity\Remove-NetFirewallRule -ErrorAction Stop}
  Assert-WelaIngressAbsent $name
  if((RulesKey '') -cne $beforeRules -or (Key (Get-WelaIngressContext)) -cne $contextKey){throw 'Original rule inventory, service or profile state differs after cleanup.'}
 }catch{$errors+=$_.Exception.Message}
 if($errors.Count){throw "Fixture cleanup failed: $($errors -join '; '); primary: $primary; evidence: $root"}
 Write-Host 'Owned rule removed; original persistent rules, firewall profiles and services preserved.'
}
if($primary){throw $primary}
$global:LASTEXITCODE=0
