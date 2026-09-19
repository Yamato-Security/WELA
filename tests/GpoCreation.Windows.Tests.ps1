# Genuine Microsoft backup read + native workgroup refusal; no domain creation/import is attempted.
param([Parameter(Mandatory)][string]$OutputPath,[switch]$AllowHostedGpmcInstall)
$ErrorActionPreference='Stop'
if($env:OS -ne 'Windows_NT') {throw 'Windows is required.'}
$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/AuditProfiles.psm1') -Force
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/GpoAuditPackages.ps1')
. (Join-Path $repo 'scripts/EvtxRecovery.ps1')
. (Join-Path $repo 'scripts/AdObjectSacl.ps1')
. (Join-Path $repo 'scripts/GpoCreation.ps1')
$script:checks=0
function Assert($Value,[string]$Message){if(-not $Value){throw "FAIL: $Message"};$script:checks++}
function Reject([scriptblock]$Code,[string]$Pattern){$message='';try{& $Code|Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern, got $message"}
function New-GPO {throw 'Forbidden domain mutation in read-only native test.'}
function Import-WelaGpoNativeTarget {throw 'Forbidden domain import in read-only native test.'}
$computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
Assert ($computer.PartOfDomain -eq $false) 'Native negative test requires an actual workgroup host'
if($AllowHostedGpmcInstall) {
    if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {throw 'GPMC installation is restricted to explicitly opted-in disposable GitHub-hosted runners.'}
    Import-Module ServerManager -ErrorAction Stop
    if((Get-WindowsFeature GPMC).Installed -ne $true) {
        $installed=Install-WindowsFeature GPMC -ErrorAction Stop
        if(-not $installed.Success -or [string]$installed.RestartNeeded -ne 'No') {throw 'GPMC installation requires successful completion without a pending restart; native evidence is blocked.'}
    }
}
$null=New-WelaGpm
$before=Get-WelaEffectiveAuditPolicy;$precedenceBefore=Get-WelaRegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' SCENoApplyLegacyAuditPolicy
$root=Resolve-WelaEvtxPath $OutputPath
if(Test-Path $root){throw 'Use a fresh native artifact directory.'}
$null=New-Item -ItemType Directory $root;Protect-WelaGpoOutput $root
try {
    $url='https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%20Server%202022%20Security%20Baseline.zip'
    $expectedHash='49590cc694626d171fc934fafea6494f13ecd3843086704b7a5b98355909b8e0'
    $zipPath=Join-Path $root 'sct.zip'
    [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
    Assert ((Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $expectedHash) 'Official SCT archive matches the reviewed SHA-256 pin'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $extract=Join-Path $root 'sct';$null=New-Item -ItemType Directory $extract
    $zip=[IO.Compression.ZipFile]::OpenRead($zipPath)
    try {
        foreach($entry in $zip.Entries) {
            $destination=[IO.Path]::GetFullPath((Join-Path $extract $entry.FullName))
            if(-not $destination.StartsWith($extract+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) {throw 'Archive traversal refused.'}
        }
    } finally {$zip.Dispose()}
    [IO.Compression.ZipFile]::ExtractToDirectory($zipPath,$extract)
    $backupRoot=Join-Path $extract 'Windows Server-2022-Security-Baseline-FINAL/GPOs'
    $backupId='20fad6fb-7c6d-496e-801c-0434769847ff'
    $native=Get-WelaGpoNativeBackup $backupRoot $backupId
    $doc=Read-WelaGpoXml $native.Xml
    $sourceId=Get-WelaGpoGuid (Get-WelaGpoText $doc.DocumentElement.Identifier 'Identifier' 'http://www.microsoft.com/GroupPolicy/Types')
    Assert ($sourceId -eq 'fa0f36d8-14ce-4d94-90f7-66a01ddb07c4' -and $sourceId -ne $backupId) 'Native GPMC reads the genuine selected backup instance and distinct source GPO GUID'
    Assert ((Get-WelaGpoText $doc.DocumentElement 'Name') -ceq 'MSFT Windows Server 2022 - Member Server') 'Native report retains official source identity'
    [IO.File]::WriteAllText((Join-Path $root 'native-backup-report.xml'),$native.Xml,[Text.Encoding]::Unicode)
    $package=Join-Path $root 'package';$null=Export-WelaGpoPackage (Get-WelaGpoPackagePlan wela-2.2.0 MemberServer 20348) $package
    $config=[ordered]@{SchemaVersion=1;PackagePath=$package;BackupRoot=$backupRoot;BackupId=$backupId;Domain='example.test';DomainGuid='dddddddd-dddd-dddd-dddd-dddddddddddd';Dc='dc.example.test';Name='Read Only Native Refusal';ReviewedSha256=''}
    $configPath=Join-Path $root 'create.json';[IO.File]::WriteAllText($configPath,($config|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    Reject {Invoke-WelaGpoCreateCommand -ConfigPath $configPath} 'narrow audit payload'
    Reject {Open-WelaGpoCreationSession ([pscustomobject]$config)} 'workgroup'
    Reject {Get-WelaGpoNativeBackup $backupRoot '11111111-1111-1111-1111-111111111111'} '.'
    # The source files and overall-status method are actual native evidence; nothing is imported.
    Write-WelaGpoReceipt $root 'native-evidence.json' ([ordered]@{ArchiveUrl=$url;ArchiveSha256=$expectedHash;BackupId=$backupId;SourceGpoId=$sourceId;PowerShell=$PSVersionTable.PSVersion.ToString();NativeBackupReportObserved=$true;BroadPayloadRefused=$true;WorkgroupGuardObserved=$true;DomainCreationTested=$false;DomainImportTested=$false;DeploymentVerified=$false})
} finally {
    $after=Get-WelaEffectiveAuditPolicy;$precedenceAfter=Get-WelaRegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' SCENoApplyLegacyAuditPolicy
    $beforeKey=@($before.Keys|Sort-Object|ForEach-Object {$_+'='+$before[$_]}) -join ';';$afterKey=@($after.Keys|Sort-Object|ForEach-Object {$_+'='+$after[$_]}) -join ';'
    Assert ($beforeKey -ceq $afterKey) 'All actual native audit masks remain unchanged'
    Assert (($precedenceBefore|ConvertTo-Json -Compress) -ceq ($precedenceAfter|ConvertTo-Json -Compress)) 'Actual precedence state remains unchanged'
}
Write-Host "GPO creation native checks: $script:checks passed. Genuine GPMC backup read and negative workgroup/broad-policy checks only; positive domain import remains pending."
$global:LASTEXITCODE=0
