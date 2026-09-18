$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$script:ScriptRoot = $repo
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/SmbAuditing.ps1')
$script:assertions = 0; $script:cleanup = @()
$root = Join-Path ([IO.Path]::GetTempPath()) ('wela-smb-' + [guid]::NewGuid().ToString('N'))
$script:cleanup += $root
$null = New-Item -ItemType Directory -Path (Join-Path $root 'PolicyDefinitions') -Force
$savedWindir = $env:windir; $savedOS = $env:OS
$env:windir = $root
function Assert($Condition, [string]$Message) { if (-not $Condition) { throw "FAIL: $Message" }; $script:assertions++ }
function Write-Admx([string]$Omit = '', [string]$WrongType = '') {
    foreach ($component in @('LanmanServer', 'LanmanWorkstation')) {
        $policies = @()
        foreach ($definition in @(Get-WelaSmbAuditDefinitions | Where-Object Component -eq $component)) {
            if ($definition.Name -eq $Omit) { continue }
            $enabled = if ($definition.Name -eq $WrongType) { '<string>1</string>' } else { '<decimal value="1"/>' }
            $policies += '<policy name="' + $definition.PolicyName + '" class="Machine" key="' + ($definition.Path -replace '^HKLM:\\', '') + '" valueName="' + $definition.Name + '"><supportedOn ref="windows:SUPPORTED_Windows_11_0"/><enabledValue>' + $enabled + '</enabledValue></policy>'
        }
        '<policyDefinitions xmlns="http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions"><policies>' + ($policies -join '') + '</policies></policyDefinitions>' | Set-Content -LiteralPath (Join-Path (Join-Path $root 'PolicyDefinitions') "$component.admx") -Encoding UTF8
    }
}
function Reset-Mocks {
    $script:build = 26100; $script:productType = 1
    $script:hostFails = $false; $script:registryFails = $false; $script:runtimeFails = $false; $script:writeFails = $false
    $script:runtimeMissing = $false; $script:runtimeFollows = $true; $script:wrongTypeWrite = $false
    $script:writes = 0; $script:keysCreated = 0; $script:registry = @{}; $script:runtime = @{}; $script:onPrompt = $null
    foreach ($definition in Get-WelaSmbAuditDefinitions) {
        $id = "$($definition.Component)/$($definition.Name)"
        $script:registry[$id] = [pscustomobject]@{ KeyExists = $false; ValueExists = $false; Value = $null; Type = $null }
        $script:runtime[$id] = $false
    }
    Write-Admx
}
function Get-CimInstance {
    param($ClassName, $Property, $ErrorAction)
    if ($script:hostFails) { throw 'OS query denied' }
    [pscustomobject]@{ ProductType = $script:productType; BuildNumber = [string]$script:build; Version = "10.0.$script:build"; Caption = 'Mock Windows' }
}
function Get-WelaRegistryState {
    param($Path, $Name)
    if ($script:registryFails) { throw 'Policy read denied' }
    $component = ($Path -split '\\')[-1]
    $source = $script:registry["$component/$Name"]
    if (-not $source) { throw "Unexpected policy path $Path/$Name" }
    [pscustomobject]@{ KeyExists = $source.KeyExists; ValueExists = $source.ValueExists; Value = $source.Value; Type = $source.Type }
}
function New-WelaRegistryKey { param($Path) $script:keysCreated++ }
function Set-ItemProperty {
    param($LiteralPath, $Name, $Value, $Type, $ErrorAction)
    $definition = @(Get-WelaSmbAuditDefinitions | Where-Object { $_.Path -eq $LiteralPath -and $_.Name -eq $Name })
    Assert ($definition.Count -eq 1 -and $Value -eq 1 -and $Type -eq 'DWord') 'Only six exact audit DWORD paths can be written'
    $entries = @(Get-Content -LiteralPath (Join-Path $script:context.BackupPath 'before.jsonl') | ConvertFrom-Json)
    Assert ($entries[-1].Target.Name -eq $Name -and $entries[-1].Target.Path -eq $LiteralPath) 'Matching recovery evidence precedes the write'
    Assert ($entries[-1].Before.Capability.AdmxSha256 -and $entries[-1].Before.Policy) 'Journal retains registry state and ADMX evidence'
    if ($script:writeFails) { throw 'Policy write denied' }
    $script:writes++
    $id = "$($definition[0].Component)/$Name"
    $script:registry[$id] = [pscustomobject]@{ KeyExists = $true; ValueExists = $true; Value = 1; Type = $(if ($script:wrongTypeWrite) { 'String' } else { 'DWord' }) }
    if ($script:runtimeFollows) { $script:runtime[$id] = $true }
}
function Get-Runtime($Component) {
    if ($script:runtimeFails) { throw 'Runtime query denied' }
    $values = @{ RequireSecuritySignature = $true; EnableInsecureGuestLogons = $false }
    if (-not $script:runtimeMissing) {
        foreach ($definition in @(Get-WelaSmbAuditDefinitions | Where-Object Component -eq $Component)) { $values[$definition.Name] = $script:runtime["$Component/$($definition.Name)"] }
    }
    [pscustomobject]$values
}
function Get-SmbClientConfiguration { param($ErrorAction) Get-Runtime 'LanmanWorkstation' }
function Get-SmbServerConfiguration { param($ErrorAction) Get-Runtime 'LanmanServer' }
function Read-Host { param($Prompt) if ($script:onPrompt) { & $script:onPrompt }; 'Y' }
function New-TestContext([switch]$DryRun, [switch]$Prompt) {
    $path = Join-Path $root ([guid]::NewGuid().ToString('N'))
    $script:context = New-WelaConfigurationContext -DryRun:$DryRun -Auto:(-not $Prompt) -BackupPath $path
    return $script:context
}
try {
    Reset-Mocks
    foreach ($case in @(@(26100, 1), @(26200, 1), @(26100, 2), @(26100, 3))) {
        $script:build = $case[0]; $script:productType = $case[1]
        $plan = @(Get-WelaSmbAuditPlan)
        Assert ($plan.Count -eq 6 -and @($plan | Where-Object Status -eq ChangeRequired).Count -eq 6) 'Reviewed client/server/DC builds require the six policies when exact ADMX exists'
    }
    Reset-Mocks
    $script:build = 20348; $script:productType = 3
    $plan = @(Get-WelaSmbAuditPlan)
    Assert (@($plan | Where-Object Status -eq NotApplicable).Count -eq 6) 'Server 2022 stays unsupported even with copied newer ADMX'
    $context = New-TestContext
    Set-WelaSmbAuditControls $context $plan
    Assert ($script:writes -eq 0 -and $script:keysCreated -eq 0 -and @($context.Results | Where-Object Status -eq Skipped).Count -eq 6) 'Unsupported host gets explicit skips and no created policy keys'
    $script:build = 30000
    Assert (@(Get-WelaSmbAuditPlan | Where-Object Status -eq Unknown).Count -eq 6) 'Unreviewed future builds are Unknown'

    Reset-Mocks
    Write-Admx -Omit AuditInsecureGuestLogon
    Assert (@(Get-WelaSmbAuditPlan | Where-Object Status -eq Unknown).Count -eq 2) 'Missing local ADMX controls are individually gated'
    Write-Admx -WrongType AuditInsecureGuestLogon
    Assert (@(Get-WelaSmbAuditPlan | Where-Object Status -eq Unknown).Count -eq 2) 'An ADMX string value 1 does not authorize a DWORD policy write'
    Remove-Item -LiteralPath (Join-Path $root 'PolicyDefinitions/LanmanServer.admx')
    Assert (@(Get-WelaSmbAuditPlan | Where-Object Status -eq Unknown).Count -eq 4) 'Missing ADMX file blocks its component while preserving other controls'
    '<!DOCTYPE policyDefinitions [<!ENTITY external SYSTEM "file:///not-readable">]><policyDefinitions>&external;</policyDefinitions>' | Set-Content -LiteralPath (Join-Path $root 'PolicyDefinitions/LanmanServer.admx')
    Assert (@(Get-WelaSmbAuditPlan | Where-Object { $_.Definition.Component -eq 'LanmanServer' -and $_.Status -eq 'Unknown' }).Count -eq 3) 'ADMX external entities are rejected'

    Reset-Mocks
    $plan = @(Get-WelaSmbAuditPlan)
    $context = New-TestContext -DryRun
    Set-WelaSmbAuditControls $context $plan
    Assert ($script:writes -eq 0 -and $script:keysCreated -eq 0 -and -not (Test-Path $context.BackupPath)) 'Dry run creates no registry policy or recovery directory'
    $context = New-TestContext
    Set-WelaSmbAuditControls $context $plan
    Assert ($script:writes -eq 6 -and (Complete-WelaConfiguration $context -Scope smb-audit-policies-only).ExitCode -eq 0) 'All six exact policies are applied and runtime observations confirm them'
    $context = New-TestContext
    Set-WelaSmbAuditControls $context @(Get-WelaSmbAuditPlan)
    Assert ($script:writes -eq 6 -and @($context.Results | Where-Object Status -eq AlreadyCompliant).Count -eq 6) 'Confirmed policy/runtime state is idempotent'
    $script:registry['LanmanServer/AuditInsecureGuestLogon'].Value = 0
    Assert ((Complete-WelaConfiguration $context).ExitCode -eq 1 -and $context.Results[2].Status -eq 'Overridden') 'Final policy refresh drift changes status and exit code'

    Reset-Mocks
    $script:runtimeFollows = $false
    $context = New-TestContext
    Set-WelaSmbAuditControls $context @(Get-WelaSmbAuditPlan)
    Assert ($script:writes -eq 6 -and (Complete-WelaConfiguration $context).Failed -eq 6) 'Policy DWORD alone cannot claim effective success when runtime is observably false'
    Assert ($context.Results[0].After.Policy.Value -eq 1 -and $context.Results[0].After.Runtime.Value -eq $false) 'Failed effective read-back keeps policy and runtime separate'

    Reset-Mocks
    $script:runtimeMissing = $true
    $context = New-TestContext
    Set-WelaSmbAuditControls $context @(Get-WelaSmbAuditPlan)
    Assert ((Complete-WelaConfiguration $context).ExitCode -eq 0) 'Exact ADMX permits registry-only configuration when runtime property is absent'
    Assert ($context.Results[0].After.Runtime.Status -eq 'NotExposed' -and $context.Results[0].After.VerificationScope -like '*effective auditing not established*') 'Registry-only outcome never claims runtime confirmation'

    Reset-Mocks
    $script:wrongTypeWrite = $true
    $context = New-TestContext
    Set-WelaSmbAuditControls $context @(Get-WelaSmbAuditPlan)
    Assert ((Complete-WelaConfiguration $context).Failed -eq 6) 'Read-back rejects wrong registry type despite a numeric match'
    foreach ($errorKind in @('hostFails', 'registryFails', 'runtimeFails')) {
        Reset-Mocks
        Set-Variable -Name $errorKind -Scope Script -Value $true
        $context = New-TestContext
        Set-WelaSmbAuditControls $context @(Get-WelaSmbAuditPlan)
        Assert ($script:writes -eq 0 -and (Complete-WelaConfiguration $context).Failed -eq 6) "$errorKind becomes an explicit failure without writes"
    }
    Reset-Mocks
    $script:runtime['LanmanServer/AuditInsecureGuestLogon'] = 'False'
    Assert (@(Get-WelaSmbAuditPlan | Where-Object Status -eq Unknown).Count -eq 1) 'String False is not coerced into a true runtime Boolean'
    Reset-Mocks
    $script:writeFails = $true
    $context = New-TestContext
    Set-WelaSmbAuditControls $context @((Get-WelaSmbAuditPlan)[0])
    Assert ((Complete-WelaConfiguration $context).Failed -eq 1) 'Write errors propagate to results'
    Reset-Mocks
    $script:onPrompt = { $script:registry['LanmanServer/AuditClientDoesNotSupportEncryption'].Value = 42 }
    $context = New-TestContext -Prompt
    Set-WelaSmbAuditControls $context @((Get-WelaSmbAuditPlan)[0])
    Assert ($script:writes -eq 0 -and $context.Results[0].Status -eq 'Failed') 'Policy changes during confirmation are not overwritten with stale recovery data'

    Reset-Mocks
    $env:OS = 'Windows_NT'
    $json = Join-Path $root 'plan.json'
    $report = Invoke-WelaSmbAuditCommand -Action Plan -ResultsPath $json
    Assert ($report.ExitCode -eq 0 -and (Get-Content $json -Raw | ConvertFrom-Json).Controls.Count -eq 6) 'Public plan writes six complete controls to JSON'
    $report = Invoke-WelaSmbAuditCommand -Action Configure -DryRun -BackupPath (Join-Path $root 'dry')
    Assert ($report.DryRun -and $script:writes -eq 0 -and $report.Scope -eq 'smb-audit-policies-only') 'Public entrypoint keeps SMB scope and dry-run semantics'
    Write-Host "PASS: $script:assertions SMB audit assertions (mocked policies/runtime; real temporary ADMX parsing)."
} finally {
    $env:windir = $savedWindir; $env:OS = $savedOS
    foreach ($path in $script:cleanup) { if (Test-Path $path) { Remove-Item -LiteralPath $path -Recurse -Force } }
}
