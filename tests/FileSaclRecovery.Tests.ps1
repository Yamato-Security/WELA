$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'modules/AuditProfiles.psm1') -Force
. (Join-Path $root 'scripts/WefArrival.ps1')
. (Join-Path $root 'scripts/EvtxRecovery.ps1')
. (Join-Path $root 'scripts/FileSaclRecovery.ps1')
$script:count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Throws($Action,$Pattern){$message='';try{& $Action|Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern, got $message"}
Initialize-WelaFileSaclRecoveryNative
Assert ([Wela.FileSaclRecovery.Descriptor]::SourceSha256 -ceq (Get-FileHash (Join-Path $root 'scripts/FileSaclRecoveryNative.cs')).Hash.ToLowerInvariant()) 'Compiled helper is bound to actual source bytes.'
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-file-recovery-json-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $temp
try {
    $path=Join-Path $temp 'input.json'
    foreach($value in @('{"ExitCode":0}','{"text":"東京","SchemaVersion":1}')){
        [IO.File]::WriteAllText($path,$value,[Text.UTF8Encoding]::new($false))
        $input=Read-WelaFileSaclRecoveryInput $path
        Assert ($input.Sha256 -ceq (Get-FileHash $path).Hash.ToLowerInvariant() -and $input.Bytes -eq ([IO.File]::ReadAllBytes($path)).Length) 'Strict evidence reader hashes actual UTF-8 bytes.'
    }
    $zero=ConvertFrom-WelaEvtxJson '{"ExitCode":0}'
    Assert (($zero.ExitCode -is [int] -or $zero.ExitCode -is [long]) -and $zero.ExitCode -eq 0) 'Real JSON integer zero is accepted across engines.'
    foreach($invalid in @('{"a":1,"a":2}','{"x":NaN}','{"x":1,}','{"x":true} trailing','')){
        [IO.File]::WriteAllText($path,$invalid)
        Throws {Read-WelaFileSaclRecoveryInput $path} 'JSON|json|byte|Unexpected|Invalid|Duplicate|custom-profile'
    }
    [IO.File]::WriteAllBytes($path,[byte[]]@(0xc3,0x28));Throws {Read-WelaFileSaclRecoveryInput $path} 'translate|valid|Unable'
    $oversize=New-Object byte[] 4194305;[IO.File]::WriteAllBytes($path,$oversize);Throws {Read-WelaFileSaclRecoveryInput $path} 'four MiB'
    $artifact=Write-WelaFileSaclRecoveryArtifact $temp 'pending.json' '{"state":"Pending"}'
    Assert ($artifact.Bytes -gt 0 -and $artifact.Sha256 -ceq (Get-FileHash (Join-Path $temp 'pending.json')).Hash.ToLowerInvariant()) 'Durably flushed pending artifact is reopened and hashed.'
    Throws {Write-WelaFileSaclRecoveryArtifact $temp 'pending.json' '{}'} 'exists'
    foreach($arguments in @(@{},@{Action='Plan';PlanPath='x'},@{Action='Plan';Auto=$true},@{Action='Plan';DryRun=$true},@{Action='Restore'},@{Action='Restore';PlanPath='x';PlanHash=('a'*64);DryRun=$true;Auto=$true},@{Action='Restore';PlanPath='x';PlanHash=('a'*64);DryRun=$true;OutputPath='out'},@{Action='Restore';PlanPath='x';PlanHash=('a'*64);OutputPath='out'})) {
        Throws {Invoke-WelaFileSaclRecovery @arguments} 'requires'
    }
    if($env:OS -ne 'Windows_NT'){Throws {Get-WelaFileSaclRecoveryOperator} 'Windows'}
    Write-Host "PASS: $script:count file recovery source, strict input, durable output and argument assertions. Native descriptor semantics run separately on Windows."
} finally {Remove-Item -LiteralPath $temp -Recurse -Force}
$global:LASTEXITCODE=0
