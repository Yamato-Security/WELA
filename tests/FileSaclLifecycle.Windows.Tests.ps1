# Mutating fixture only: public WELA never registers profiles or loads hives.
param([switch]$AllowDisposableProfileWrite)
$ErrorActionPreference='Stop'
if(-not $AllowDisposableProfileWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or [Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess){throw 'Explicit disposable hosted native Windows fixture only.'}
$script:ScriptRoot=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $script:ScriptRoot 'modules/AuditProfiles.psm1') -ErrorAction Stop
foreach($name in @('Configuration','WefArrival','WmiProbe','ChannelRead','SelectedSaclConfiguration','FileAccessProbe')){. (Join-Path $script:ScriptRoot ('scripts/'+$name+'.ps1'))}
Initialize-WelaWmiProbeNative
Add-Type -Path (Join-Path $PSScriptRoot 'RegistrySaclFixtureNative.cs') -ErrorAction Stop
Add-Type -Path (Join-Path $PSScriptRoot 'FileSaclProfileFixture.cs') -ErrorAction Stop
$nonce=[guid]::NewGuid().ToString('N')
$evidence=New-WelaArrivalOutput (Join-Path $env:RUNNER_TEMP ('wela-filesystem-lifecycle-'+$nonce)) $script:ScriptRoot
$targetRoot=New-WelaArrivalOutput (Join-Path (Join-Path $env:SystemRoot 'Temp') ('wela-filesystem-sacl-'+$nonce)) $script:ScriptRoot
$files=Join-Path $evidence 'owned-hive-files';$null=New-Item -ItemType Directory $files
function Save([string]$Name,$Value){[IO.File]::WriteAllText((Join-Path $evidence $Name),(ConvertTo-Json -InputObject $Value -Depth 32),[Text.UTF8Encoding]::new($false))}
function Key($Value){ConvertTo-Json -InputObject $Value -Depth 32 -Compress}
function Hives {@([Microsoft.Win32.Registry]::Users.GetSubKeyNames()|Sort-Object)}
$script:assertions=0
function Assert($Condition,[string]$Message){if(-not $Condition){throw $Message};$script:assertions++}
$beforeProfiles=[Wela.FileSaclFixture.Profile]::Snapshot();$beforeHives=Hives;$beforeToken=[Wela.WmiProbe.Native]::Snapshot()
$beforeMasks=Get-WelaEffectiveAuditPolicy;$precedencePath='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';$precedenceName='SCENoApplyLegacyAuditPolicy';$beforePrecedence=Get-WelaRegistryState $precedencePath $precedenceName
Save 'before-profiles.json' $beforeProfiles;Save 'before-hives.json' $beforeHives;Save 'before-token.json' $beforeToken;Save 'before-masks.json' $beforeMasks;Save 'before-precedence.json' $beforePrecedence
$hive=[Wela.RegistrySaclFixture.Hive]::new($nonce,(Join-Path $files 'owned.dat'));$profile=$null;$failure=$null;$cleanupErrors=@()
try {
    $hive.Prepare();$profile=[Wela.FileSaclFixture.Profile]::new($nonce,$hive.Sid,$targetRoot);$profile.Prepare()
    $signal=Join-Path $profile.AppDataPath 'Signal';$null=New-Item -ItemType Directory $signal
    $context=Get-WelaSelectedSaclContext
    $catalog=Get-WelaSelectedSaclCatalog -Profile 'asd-native-2021-10' -IncludeOptional -Context $context
    Save 'catalog.json' $catalog;Save 'owned-profile.json' ([pscustomobject]@{Sid=$hive.Sid;Nonce=$nonce;Root=$targetRoot;ProfilePath=$profile.ProfilePath;AppDataPath=$profile.AppDataPath;SelectedPath=$signal})
    $selected=@($catalog.Rows|Where-Object {$_.Definition.UserSid -ceq $hive.Sid -and $_.Definition.Kind -ceq 'FileSystem' -and $_.Definition.Path -ieq $signal})
    Assert ($selected.Count -eq 1 -and $selected[0].Definition.Resolution -ceq 'Redirected') 'Real built-in catalog resolves exactly the owned redirected Signal folder.'
    Assert ($selected[0].Definition.PrincipalSid -ceq 'S-1-1-0' -and @($selected[0].Definition.Rights).Count -eq 1 -and $selected[0].Definition.Rights[0] -ceq 'ReadData') 'Owned fixture uses the unchanged built-in read target.'
    Assert ((Key (Hives)) -ceq (Key (@($beforeHives)+$hive.Sid|Sort-Object))) 'Only the owned hive was mounted.'
    $profile.AssertOwned();$hive.AssertOwned()
    Assert (([Wela.FileSaclFixture.Profile]::Snapshot()).Children.Count -eq $beforeProfiles.Children.Count+1) 'Exactly one marker-owned profile entry was registered.'
    Assert ((Key ([Wela.WmiProbe.Native]::Snapshot())) -ceq (Key $beforeToken)) 'Fixture profile/hive preparation restores full token state.'
}catch{$failure=$_}finally{
    try{if($profile){$profile.Dispose()}}catch{$cleanupErrors+='Profile removal: '+$_.Exception.Message}
    try{$hive.Dispose()}catch{$cleanupErrors+='Hive unload/seed removal: '+$_.Exception.Message}
    $afterProfiles=$null;$afterHives=$null;$afterToken=$null;$afterMasks=$null;$afterPrecedence=$null
    $profilesOk=$false;$hivesOk=$false;$tokenOk=$false;$masksOk=$false;$precedenceOk=$false
    try{$afterProfiles=[Wela.FileSaclFixture.Profile]::Snapshot();$profilesOk=(Key $afterProfiles) -ceq (Key $beforeProfiles)}catch{$cleanupErrors+='Profile verification: '+$_.Exception.Message}
    try{$afterHives=Hives;$hivesOk=(Key $afterHives) -ceq (Key $beforeHives)}catch{$cleanupErrors+='Hive verification: '+$_.Exception.Message}
    try{$afterToken=[Wela.WmiProbe.Native]::Snapshot();$tokenOk=(Key $afterToken) -ceq (Key $beforeToken)}catch{$cleanupErrors+='Token verification: '+$_.Exception.Message}
    try{$afterMasks=Get-WelaEffectiveAuditPolicy;$masksOk=(Key ($afterMasks.GetEnumerator()|Sort-Object Key)) -ceq (Key ($beforeMasks.GetEnumerator()|Sort-Object Key))}catch{$cleanupErrors+='Audit verification: '+$_.Exception.Message}
    try{$afterPrecedence=Get-WelaRegistryState $precedencePath $precedenceName;$precedenceOk=(Key $afterPrecedence) -ceq (Key $beforePrecedence)}catch{$cleanupErrors+='Precedence verification: '+$_.Exception.Message}
    if($profilesOk -and $hivesOk -and -not $hive.Loaded){try{Remove-Item -LiteralPath $targetRoot -Recurse -Force -ErrorAction Stop;Remove-Item -LiteralPath $files -Recurse -Force -ErrorAction Stop}catch{$cleanupErrors+='Owned file removal: '+$_.Exception.Message}}
    $cleanup=[pscustomobject]@{Complete=($profilesOk -and $hivesOk -and $tokenOk -and $masksOk -and $precedenceOk -and -not $hive.Loaded -and -not $hive.SeedCreated -and -not(Test-Path $targetRoot) -and -not(Test-Path $files) -and $cleanupErrors.Count -eq 0);ProfilesRestored=$profilesOk;HivesRestored=$hivesOk;TokenRestored=$tokenOk;AuditMasksCompared=$beforeMasks.Count;AuditMasksRestored=$masksOk;PrecedenceRestored=$precedenceOk;HiveUnloaded=(-not $hive.Loaded);SeedRemoved=(-not $hive.SeedCreated);FilesRemoved=(-not(Test-Path $targetRoot) -and -not(Test-Path $files));Errors=$cleanupErrors;Failure=$(if($failure){$failure.Exception.Message}else{$null});Assertions=$script:assertions;AfterProfiles=$afterProfiles;AfterHives=$afterHives;AfterToken=$afterToken;AfterMasks=$afterMasks;AfterPrecedence=$afterPrecedence}
    Save 'cleanup.json' $cleanup
    Save 'artifact-hashes.json' @(Get-ChildItem -LiteralPath $evidence -Recurse -File|Where-Object Name -ne 'artifact-hashes.json'|Sort-Object FullName|ForEach-Object {[pscustomobject]@{Name=$_.FullName.Substring($evidence.Length+1).Replace('\','/');Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}})
}
if($failure){throw $failure};if(-not $cleanup.Complete){throw ('Owned profile fixture cleanup incomplete: '+(Key $cleanup))}
Write-Host "Passed $script:assertions owned native profile substrate assertions; cleanup confirmed. Evidence: $evidence"
$global:LASTEXITCODE=0
