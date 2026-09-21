param([switch]$AllowDisposableHiveWrite)
$ErrorActionPreference='Stop'
if(-not $AllowDisposableHiveWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or [Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess){throw 'Explicit disposable GitHub-hosted native Windows fixture only.'}
$script:ScriptRoot=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $script:ScriptRoot 'modules/AuditProfiles.psm1') -ErrorAction Stop
foreach($name in @('Configuration','WefArrival','WmiProbe')){. (Join-Path $script:ScriptRoot ('scripts/'+$name+'.ps1'))}
Initialize-WelaWmiProbeNative
Add-Type -Path (Join-Path $PSScriptRoot 'RegistrySaclFixtureNative.cs') -ErrorAction Stop
$root=New-WelaArrivalOutput (Join-Path $env:RUNNER_TEMP ('wela-registry-sacl-'+[guid]::NewGuid().ToString('N'))) $script:ScriptRoot
$files=Join-Path $root 'owned-hive-files';$null=New-Item -ItemType Directory $files
function Save([string]$Name,$Value){[IO.File]::WriteAllText((Join-Path $root $Name),($Value|ConvertTo-Json -Depth 28),[Text.UTF8Encoding]::new($false))}
function Hives {@([Microsoft.Win32.Registry]::Users.GetSubKeyNames()|Sort-Object)}
function Key($Value){ConvertTo-Json -InputObject $Value -Depth 20 -Compress}
$beforeHives=Hives;$beforeToken=[Wela.WmiProbe.Native]::Snapshot();$beforeMasks=Get-WelaEffectiveAuditPolicy;$beforePrecedence=Get-WelaRegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' SCENoApplyLegacyAuditPolicy
Save 'before-hives.json' $beforeHives;Save 'before-token.json' $beforeToken;Save 'before-masks.json' $beforeMasks;Save 'before-precedence.json' $beforePrecedence
$hive=[Wela.RegistrySaclFixture.Hive]::new([guid]::NewGuid().ToString('N'),(Join-Path $files 'owned.dat'));$failure='';$errors=@();$assertions=0
try {
    $hive.Prepare();$hive.CreateRunOnce();$hive.AssertOwned()
    $mounted=Hives;if((Key $mounted) -cne (Key (@($beforeHives)+$hive.Sid|Sort-Object))){throw 'Unexpected HKU namespace change.'};$assertions++
    Save 'mounted.json' ([pscustomobject]@{Sid=$hive.Sid;File=$hive.FilePath;Seed=$hive.SeedPath;Loaded=$hive.Loaded;Target=('Registry::HKEY_USERS\'+$hive.Sid+'\Software\Microsoft\Windows\CurrentVersion\RunOnce')})
    if((Key ([Wela.WmiProbe.Native]::Snapshot())) -cne (Key $beforeToken)){throw 'Fixture preparation did not restore the primary token.'};$assertions++
    $engine=(Get-Process -Id $PID).Path;$old=$ErrorActionPreference
    try{$ErrorActionPreference='Continue';$out=@(& $engine -NoLogo -NoProfile -NonInteractive -File (Join-Path $script:ScriptRoot 'WELA.ps1') targeted-sacl -TargetSaclProfile asd-native-2021-10 -IncludeOptional -ResultsPath (Join-Path $root 'catalog.json') 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$old;$global:LASTEXITCODE=0}
    Save 'catalog-output.json' $out
    if($code -ne 0){throw "Actual public catalog exited $code : $($out -join ' ')"}
    $catalog=ConvertFrom-WelaArrivalJson ([IO.File]::ReadAllText((Join-Path $root 'catalog.json')))
    $matches=@($catalog.Catalog|Where-Object {$_.Definition.UserSid -ceq $hive.Sid -and $_.Definition.Path -ieq ('Registry::HKEY_USERS\'+$hive.Sid+'\Software\Microsoft\Windows\CurrentVersion\RunOnce')})
    if($matches.Count -ne 1 -or $matches[0].Id -cnotmatch '^sacl-[a-f0-9]{24}$' -or $matches[0].Definition.Resolution -cne 'Resolved'){throw 'The unchanged actual public catalog did not resolve exactly one owned registry target.'};$assertions++
    Save 'selected.json' $matches[0]
} catch {$failure=$_.Exception.Message;throw} finally {
    try{$hive.Dispose()}catch{$errors+=$_.Exception.Message}
    $hivesOk=(Key (Hives)) -ceq (Key $beforeHives);$tokenOk=(Key ([Wela.WmiProbe.Native]::Snapshot())) -ceq (Key $beforeToken)
    $masks=Get-WelaEffectiveAuditPolicy;$masksOk=(Key ($masks.GetEnumerator()|Sort-Object Key)) -ceq (Key ($beforeMasks.GetEnumerator()|Sort-Object Key));$precedenceOk=(Key (Get-WelaRegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' SCENoApplyLegacyAuditPolicy)) -ceq (Key $beforePrecedence)
    if(-not $hive.Loaded -and $hivesOk){try{Remove-Item -LiteralPath $files -Recurse -Force -ErrorAction Stop}catch{$errors+=$_.Exception.Message}}
    $cleanup=[pscustomobject]@{Complete=($hivesOk -and $tokenOk -and $masksOk -and $precedenceOk -and -not $hive.SeedCreated -and -not(Test-Path $files) -and $errors.Count -eq 0);HivesRestored=$hivesOk;TokenRestored=$tokenOk;AuditMasksRestored=$masksOk;PrecedenceRestored=$precedenceOk;HiveUnloaded=(-not $hive.Loaded);SeedRemoved=(-not $hive.SeedCreated);FilesRemoved=(-not(Test-Path $files));Errors=$errors;Failure=$failure;Assertions=$assertions;AfterHives=(Hives);AfterToken=[Wela.WmiProbe.Native]::Snapshot();AfterMasks=$masks;AfterPrecedence=(Get-WelaRegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' SCENoApplyLegacyAuditPolicy)}
    Save 'cleanup.json' $cleanup
    if(-not $cleanup.Complete){throw ('Owned registry fixture cleanup incomplete: '+(Key $cleanup))}
}
Write-Host "Passed $assertions owned real hive/catalog checkpoint assertions; all cleanup confirmed. Evidence: $root"
$global:LASTEXITCODE=0
