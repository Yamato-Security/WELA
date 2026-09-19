# Real native APIs and public CLI. Never dot-source mocked fixture functions.
param([switch]$AllowDisposableNamespaceWrite)
$ErrorActionPreference='Stop'
if(-not $AllowDisposableNamespaceWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:OS -ne 'Windows_NT'){throw 'Explicit disposable GitHub-hosted Windows opt-in is required.'}
$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/AuditProfiles.psm1') -Force
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/ControlApplicability.ps1')
. (Join-Path $repo 'scripts/WefArrival.ps1')
. (Join-Path $repo 'scripts/WmiNamespaceAuditing.ps1')
. (Join-Path $repo 'scripts/WmiProbe.ps1')
$context=Get-WelaDefaultContext
if(-not(Test-WelaDefaultContextComplete $context) -or $context.Build -notin @(20348,26100) -or $context.ProductType -ne 3 -or $context.DomainRole -ne 2 -or $context.DomainJoined){throw 'Only an observed disposable workgroup Server2022/2025 is permitted.'}
$script:count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function PolicyKey($Map){(@($Map.Keys|Sort-Object|ForEach-Object{"$_=$($Map[$_])"}) -join ';')}
$engine=(Get-Process -Id $PID).Path
$guid='0CCE9227-69AE-11D9-BED3-505054503030'
$path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';$name='SCENoApplyLegacyAuditPolicy'
$originalPolicies=Get-WelaEffectiveAuditPolicy;$originalPrecedence=Get-WelaRegistryState $path $name
Initialize-WelaWmiProbeNative
$originalToken=[Wela.WmiProbe.Native]::Snapshot()
$namespaceName='WelaReadTest_'+[guid]::NewGuid().ToString('N');$namespace='root\'+$namespaceName
$private=New-WelaArrivalOutput (Join-Path ([IO.Path]::GetTempPath()) ('wela-wmi-native-'+[guid]::NewGuid().ToString('N'))) $PSScriptRoot
$created=$false;$instance=$null;$factory=$null;$failure=$null;$cleanupErrors=@()
try{
    Initialize-WelaWmiInterop
    $factory=New-Object System.Management.ManagementClass -ArgumentList '\\.\root:__Namespace'
    $instance=$factory.CreateInstance();$instance.Name=$namespaceName
    $options=New-Object System.Management.PutOptions;$options.Type=[System.Management.PutType]::CreateOnly
    $createdPath=$instance.Put($options);$created=$true
    Assert ($createdPath.RelativePath -ieq ('__NAMESPACE.Name="'+$namespaceName+'"')) 'CreateOnly returned the exact owned namespace.'
    $before=Get-WelaWmiNamespaceSnapshot $namespace
    $defs=@(Get-WelaWmiAuditDefinitions -Namespace 'root\default')
    $defs[0].Namespace=$namespace
    $config=New-WelaConfigurationContext -Auto -BackupPath (Join-Path $private 'sacl-before')
    Set-WelaWmiAuditControls -Context $config -Plan @([pscustomobject]@{Namespace=$namespace;Definitions=$defs})
    $configured=Complete-WelaConfiguration -Context $config -Scope 'wmi-namespace-sacl-only'
    Assert ($configured.ExitCode -eq 0 -and $configured.Results[0].Status -eq 'Applied') 'Real production writer configured only the owned namespace.'
    $after=Get-WelaWmiNamespaceSnapshot $namespace
    Assert (Test-WelaWmiDescriptorPreserved ($before.DescriptorJson|ConvertFrom-Json) ($after.DescriptorJson|ConvertFrom-Json)) 'Owner/group/DACL and existing SACL entries survived.'
    Set-ItemProperty -LiteralPath $path -Name $name -Type DWord -Value 1
    Set-WelaEffectiveAuditPolicy -Guid $guid -Mask 1 -Mode minimum
    $out=Join-Path $private 'probe'
    $ErrorActionPreference='Continue'
    $cli=& $engine -NoLogo -NoProfile -NonInteractive -File (Join-Path $repo 'WELA.ps1') wmi-probe -WmiProbeAction Run -WmiProbeNamespace $namespace -WmiProbeOutputPath $out -WmiProbeTimeoutSeconds 20 2>&1|Out-String
    $code=$LASTEXITCODE;$ErrorActionPreference='Stop'
    $manifest=ConvertFrom-WelaArrivalJson ([IO.File]::ReadAllText((Join-Path $out 'manifest.json')))
    # Bounded raw native diagnostics are useful when an unreviewed OS schema differs.
    Write-Host ($manifest|ConvertTo-Json -Depth 18)
    foreach($file in @(Get-ChildItem -LiteralPath $out -Filter '*.xml' -ErrorAction Stop)){Write-Host ([IO.File]::ReadAllText($file.FullName))}
    Assert ($code -eq 0 -and $manifest.Status -eq 'LocalNamespaceAccessObserved' -and $manifest.ExitCode -eq 0) ('Public native probe failed: '+$manifest.Diagnostic+' '+$cli)
    Assert ($manifest.Matches -ge 1 -and $manifest.Matches -le 16 -and $manifest.ReadyRuleCredit -eq 0 -and $manifest.PolicyChanges -eq 0 -and $manifest.NamespaceChanges -eq 0) 'Bounded native evidence grants no policy or Sigma claim.'
    foreach($artifact in $manifest.Artifacts){Assert ($artifact.Sha256 -ceq (Get-FileHash -LiteralPath (Join-Path $out $artifact.Name)).Hash.ToLowerInvariant()) 'Protected artifact hash verifies.'}
    foreach($file in @(Get-ChildItem -LiteralPath $out -Filter 'event-*.xml')){Assert (Test-WelaWmiProbeEvent ([IO.File]::ReadAllText($file.FullName)) $manifest.Operation $manifest.Before) 'Real WMI event passes exact source/namespace/token/mask/time checks.'}
    Assert ((Get-WelaWmiNamespaceSnapshot $namespace).DescriptorJson -ceq $after.DescriptorJson) 'Public probe made no namespace security changes.'
    Assert ((Get-WelaWmiProbeTokenKey ([Wela.WmiProbe.Native]::Snapshot())) -ceq (Get-WelaWmiProbeTokenKey $originalToken)) 'Native descriptor reads/writes restored caller token state.'
    Assert ((Get-Acl -LiteralPath $out).AreAccessRulesProtected) 'Evidence directory blocks inherited broad access.'
}catch{$failure=$_}
finally{
    try{Set-WelaEffectiveAuditPolicy -Guid $guid -Mask $originalPolicies[$guid] -Mode exact}catch{$cleanupErrors+='Audit restoration: '+$_.Exception.Message}
    try{if($originalPrecedence.ValueExists){Set-ItemProperty -LiteralPath $path -Name $name -Type $originalPrecedence.Type -Value $originalPrecedence.Value}else{Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop}}catch{$cleanupErrors+='Precedence restoration: '+$_.Exception.Message}
    try{Assert ((PolicyKey (Get-WelaEffectiveAuditPolicy)) -ceq (PolicyKey $originalPolicies)) 'All59 original native audit masks restored.';Assert (((Get-WelaRegistryState $path $name)|ConvertTo-Json -Compress) -ceq ($originalPrecedence|ConvertTo-Json -Compress)) 'Typed original precedence restored.'}catch{$cleanupErrors+='Policy verification: '+$_.Exception.Message}
    try{if($created){$instance.Delete();$left=@(Get-CimInstance -Namespace root -ClassName __Namespace -Filter ("Name='$namespaceName'") -ErrorAction Stop);Assert ($left.Count -eq 0) 'Only the owned temporary namespace was removed.'}}catch{$cleanupErrors+='Namespace cleanup: '+$_.Exception.Message}
    if($instance){$instance.Dispose()};if($factory){$factory.Dispose()}
    [pscustomobject]@{Namespace=$namespace;Created=$created;Failure=$(if($failure){$failure.Exception.Message}else{$null});CleanupErrors=$cleanupErrors;Evidence=$private;Complete=($null -eq $failure -and $cleanupErrors.Count -eq 0)}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $private 'cleanup.json') -Encoding UTF8
}
if($failure){throw $failure};if($cleanupErrors.Count){throw ($cleanupErrors -join '; ')}
Write-Host "PASS: $script:count actual native WMI4662/public CLI assertions, original policies restored and owned namespace removed. No remote or Sigma claim."
$global:LASTEXITCODE=0
