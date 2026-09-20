# Windows-only read-only native observations. The output directory is an owned test artifact.
param([Parameter(Mandatory)][string]$OutputPath,[string]$VerifyOtherPath)
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') {throw 'This smoke test requires Windows.'}
$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/AuditProfiles.psm1') -Force
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/GpoAuditPackages.ps1')
function New-GPO {throw 'Domain creation is forbidden in this read-only test.'}
function Import-GPO {throw 'Domain import is forbidden in this read-only test.'}
function Set-WelaEffectiveAuditPolicy {throw 'Native audit mutation is forbidden in this read-only test.'}
function Set-ItemProperty {throw 'Registry mutation is forbidden in this read-only test.'}
$script:checks=0
function Assert($Value,[string]$Message){if(-not $Value){throw "FAIL: $Message"};$script:checks++}
function PolicyFingerprint($State) {(@($State.Keys|Sort-Object|ForEach-Object {$_+'='+$State[$_]})-join ';')}
$before=Get-WelaEffectiveAuditPolicy
$precedenceBefore=Get-WelaRegistryState -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy
Assert ($before.Count -eq 59) 'Native API reads the actual 59 subcategory masks'
try {
    # Explicit target is a package input, regardless of the Server runner's actual role/build.
    $plan=Get-WelaGpoPackagePlan -Profile wela-2.2.0 -Role Client -Build 26100
    $export=Export-WelaGpoPackage -Plan $plan -Path $OutputPath
    Assert ($export.ExitCode -eq 0 -and $export.Plan.Role -eq 'Client' -and -not $export.DeploymentVerified) 'Package target remains declared without host/application claims'
    $null=Invoke-WelaNative -FilePath (Join-Path $env:SystemRoot 'System32/secedit.exe') -Arguments @('/validate',(Join-Path $OutputPath 'GptTmpl.inf'))
    Assert $true 'Native secedit validates security-template syntax only'
    $verified=Test-WelaGpoPackage -Path $OutputPath
    Assert ($verified.ExitCode -eq 0) 'Template validation leaves the generated package intact'
    if ($VerifyOtherPath) {
        $other=Test-WelaGpoPackage -Path $VerifyOtherPath
        Assert ($other.ExitCode -eq 0) 'Package created by the other PowerShell edition verifies against this generator'
        foreach ($name in @('audit.csv','GptTmpl.inf','review.md','deployment.md')) {
            $left=Get-FileHash -LiteralPath (Join-Path $OutputPath $name) -Algorithm SHA256
            $right=Get-FileHash -LiteralPath (Join-Path $VerifyOtherPath $name) -Algorithm SHA256
            Assert ($left.Hash -eq $right.Hash) "Both editions generate identical $name bytes"
        }
    }
} finally {
    $after=Get-WelaEffectiveAuditPolicy
    $precedenceAfter=Get-WelaRegistryState -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy
    Assert ((PolicyFingerprint $before) -ceq (PolicyFingerprint $after)) 'All effective native audit masks remain unchanged'
    Assert ((ConvertTo-Json $precedenceBefore -Compress) -ceq (ConvertTo-Json $precedenceAfter -Compress)) 'Precedence registry presence/type/value remain unchanged'
}
Write-Host "PASS: $script:checks read-only GPO component checks. No local/domain policy application; retain package for cross-edition verification."
