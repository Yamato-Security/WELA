# Native public CLI only: fixture prepares auditing, product never changes it.
param([switch]$AllowDisposableAuditWrite,[ValidateRange(1,3)][int]$ProbeRuns=2)
$ErrorActionPreference='Stop'
if(-not $AllowDisposableAuditWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:OS -ne 'Windows_NT'){throw 'Explicit disposable GitHub-hosted Windows opt-in is required.'}
$repo=Split-Path $PSScriptRoot -Parent;$script:ScriptRoot=$repo
Import-Module "$repo/modules/AuditProfiles.psm1" -Force
. "$repo/scripts/Configuration.ps1"
. "$repo/scripts/ControlApplicability.ps1"
. "$repo/scripts/WefArrival.ps1"
. "$repo/scripts/ChannelRead.ps1"
. "$repo/scripts/FailedLogonProbe.ps1"
$context=Get-WelaDefaultContext
if(-not(Test-WelaDefaultContextComplete $context) -or $context.Build -notin @(20348,26100) -or $context.ProductType -ne 3 -or $context.DomainRole -ne 2 -or $context.DomainJoined){throw 'Only observed disposable workgroup Server2022/2025 is permitted.'}
$script:count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function PolicyKey($Map){(@($Map.Keys|Sort-Object|ForEach-Object{"$_=$($Map[$_])"}) -join ';')}
function AccountsKey {(@(Get-LocalUser -ErrorAction Stop|ForEach-Object {"$($_.SID.Value)=$($_.Name)=$($_.Enabled)"}|Sort-Object) -join ';')}
$engine=(Get-Process -Id $PID).Path;$guid='0CCE9215-69AE-11D9-BED3-505054503030'
$path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';$name='SCENoApplyLegacyAuditPolicy'
$policies=Get-WelaEffectiveAuditPolicy;$precedence=Get-WelaRegistryState $path $name;$accounts=AccountsKey
$root=Join-Path $env:RUNNER_TEMP ('wela-failed-logon-native-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
$failure=$null;$cleanupErrors=@()
try{
 Set-ItemProperty -LiteralPath $path -Name $name -Type DWord -Value 1
 Set-WelaEffectiveAuditPolicy -Guid $guid -Mask 2 -Mode minimum
 $preparedPolicies=PolicyKey (Get-WelaEffectiveAuditPolicy)
 for($trial=1;$trial -le $ProbeRuns;$trial++){
  $out=Join-Path $root ('probe-'+$trial)
  $ErrorActionPreference='Continue';$cli=&$engine -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$repo/WELA.ps1" failed-logon-probe -FailedLogonAction Run -FailedLogonOutputPath $out -FailedLogonTimeoutSeconds 20 2>&1|Out-String;$code=$LASTEXITCODE;$ErrorActionPreference='Stop'
  $manifest=ConvertFrom-WelaArrivalJson ([IO.File]::ReadAllText((Join-Path $out 'manifest.json')))
  Write-Host ($manifest|ConvertTo-Json -Depth 18)
  foreach($file in @(Get-ChildItem -LiteralPath $out -Filter '*.xml')){Write-Host ([IO.File]::ReadAllText($file.FullName))}
  Assert ($code -eq 0 -and $manifest.Status -eq 'LocalFailedLogonObserved' -and $manifest.ExitCode -eq 0) ('Native public probe failed: '+$manifest.Diagnostic+' '+$cli)
  Assert ($manifest.Matches -eq 1 -and $manifest.ReadyRuleCredit -eq 0 -and $manifest.PolicyChanges -eq 0 -and $manifest.AccountChanges -eq 0) 'One exact event, no mutation or Sigma credit.'
  Assert ($manifest.Operation.Attempt.NativeError -eq 1326 -and $manifest.Operation.Attempt.MissingAccountStatus -eq 2221 -and -not $manifest.Operation.Attempt.Succeeded) 'Actual local account absence and failed LogonUser receipt.'
  Assert (Test-WelaFailedLogonEvent ([IO.File]::ReadAllText((Join-Path $out 'event.xml'))) $manifest.Operation $manifest.Before) 'Actual4625 satisfies exact identity/process/type/status/time checks.'
  foreach($artifact in $manifest.Artifacts){Assert ($artifact.Sha256 -ceq (Get-FileHash -LiteralPath (Join-Path $out $artifact.Name)).Hash.ToLowerInvariant()) 'Native evidence hash verified.'}
  Assert ((PolicyKey (Get-WelaEffectiveAuditPolicy)) -ceq $preparedPolicies) 'Product leaves every audit mask unchanged.'
  Assert ((AccountsKey) -ceq $accounts) 'Local account names/SIDs/enabled states unchanged.'
  Assert ((Get-Acl -LiteralPath $out).AreAccessRulesProtected) 'Evidence directory inheritance is protected.'
 }
}catch{$failure=$_}
finally{
 try{Set-WelaEffectiveAuditPolicy -Guid $guid -Mask $policies[$guid] -Mode exact}catch{$cleanupErrors+='Audit restoration: '+$_.Exception.Message}
 try{if($precedence.ValueExists){Set-ItemProperty -LiteralPath $path -Name $name -Type $precedence.Type -Value $precedence.Value}else{Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop}}catch{$cleanupErrors+='Precedence restoration: '+$_.Exception.Message}
 try{Assert ((PolicyKey (Get-WelaEffectiveAuditPolicy)) -ceq (PolicyKey $policies)) 'All59 original audit masks restored.';Assert (((Get-WelaRegistryState $path $name)|ConvertTo-Json -Compress) -ceq ($precedence|ConvertTo-Json -Compress)) 'Typed original precedence restored.';Assert ((AccountsKey) -ceq $accounts) 'No local accounts changed.'}catch{$cleanupErrors+='Verification: '+$_.Exception.Message}
 [ordered]@{CleanupVerified=($cleanupErrors.Count -eq 0);AuditMasksCompared=$policies.Count;ProbeRuns=$ProbeRuns;AssertionCount=$count;Failure=$(if($failure){$failure.Exception.Message}else{$null});CleanupErrors=$cleanupErrors}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $root 'cleanup.json') -Encoding UTF8
}
if($failure){throw $failure};if($cleanupErrors.Count){throw ($cleanupErrors -join '; ')}
Write-Host "PASS: $script:count actual native4625/public CLI assertions across $ProbeRuns independent runs; original policies restored, no local account changes."
$global:LASTEXITCODE=0
