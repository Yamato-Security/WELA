# Profile command + verified configuration integration. No Windows policy is touched.
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$script:ScriptRoot = $repo
Import-Module (Join-Path $repo 'modules/AuditProfiles.psm1') -Force
. (Join-Path $repo 'scripts/Configuration.ps1')
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'WELA.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
foreach ($name in @('Get-WelaSelectedContext', 'Show-WelaAuditProfilePrerequisites', 'Invoke-WelaProfileCommand', 'ConfigureAuditSettings')) {
    $function = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    . ([scriptblock]::Create($function.Extent.Text))
}
$script:assertions = 0
$script:cleanup = New-Object 'System.Collections.Generic.List[string]'
$data = Import-WelaAuditProfiles
$zero = @{}
foreach ($policy in $data.catalog) { $zero[$policy.guid] = 0 }
$shareGuid = ($data.catalog | Where-Object id -eq 'Detailed File Share').guid
$processGuid = ($data.catalog | Where-Object id -eq 'Process Creation').guid
$privilegeGuid = ($data.catalog | Where-Object id -eq 'Sensitive Privilege Use').guid
function Assert($Condition, [string]$Message) {
    if (-not $Condition) { throw "FAIL: $Message" }
    $script:assertions++
}
function Assert-Throws([scriptblock]$Action, [string]$Pattern) {
    $caught = ''
    try { & $Action | Out-Null } catch { $caught = $_.ToString() }
    Assert ($caught -match $Pattern) "Expected failure matching '$Pattern', got '$caught'"
}
function Reset-Run([string]$Profile = 'cis-win11-v4-l1', [switch]$DryRun) {
    $script:state = $zero.Clone()
    $script:writes = @()
    $script:failGuid = ''
    $script:concurrentGuid = ''
    $script:Profile = $Profile
    $script:Role = 'Client'; $script:Build = 26100
    $script:hostBuild = 26100
    $script:Baseline = $null; $script:IncludeOptional = $false
    $script:Auto = $true; $script:DryRun = [bool]$DryRun
    $script:BackupPath = Join-Path ([IO.Path]::GetTempPath()) ('wela-profile-integration-' + [guid]::NewGuid().ToString('N'))
    $script:ResultsPath = $script:BackupPath + '-results.json'
    $script:PlanPath = $null
    $script:cleanup.Add($script:BackupPath)
    $script:cleanup.Add($script:ResultsPath)
}
function global:TestWindows { return $true }
function global:TestAdministrator { return $true }
function global:Get-WelaHostContext { [pscustomobject]@{ Role = 'Client'; Build = $script:hostBuild } }
function global:Get-WelaEffectiveAuditPolicy { return $script:state.Clone() }
function global:Get-WelaNativeAuditPolicy {
    param($Guid)
    if (-not $script:state.ContainsKey($Guid)) { throw "Mock missing policy: $Guid" }
    return $script:state[$Guid]
}
function global:Invoke-WelaNative {
    param($FilePath, $Arguments)
    if ($FilePath -ne 'auditpol.exe' -or $Arguments[0] -ne '/set') { throw 'Unexpected native mutation' }
    $guid = ($Arguments | Where-Object { $_ -like '/subcategory:*' }) -replace '^/subcategory:\{([^}]+)\}$', '$1'
    $journal = Join-Path $script:BackupPath 'before.jsonl'
    if (-not (Test-Path -LiteralPath $journal)) { throw 'Audit mutation occurred before journal' }
    $entries = @(Get-Content -LiteralPath $journal | ConvertFrom-Json)
    if ($entries[-1].Target.Guid -ne $guid) { throw 'Audit mutation occurred before matching journal entry' }
    if ($guid -eq $script:failGuid) { throw 'Mock auditpol write failure' }
    # Simulate a concurrent writer enabling Failure after WELA observed the policy.
    if ($guid -eq $script:concurrentGuid) { $script:state[$guid] = $script:state[$guid] -bor 2 }
    $mask = $script:state[$guid]
    foreach ($arg in $Arguments) {
        switch ($arg) {
            '/success:enable' { $mask = $mask -bor 1 }
            '/success:disable' { $mask = $mask -band 2 }
            '/failure:enable' { $mask = $mask -bor 2 }
            '/failure:disable' { $mask = $mask -band 1 }
        }
    }
    $script:state[$guid] = $mask
    $script:writes += [pscustomobject]@{ Guid = $guid; Arguments = $Arguments }
    [pscustomobject]@{ ExitCode = 0; Diagnostic = ''; Output = @() }
}
try {
    Reset-Run -DryRun
    Invoke-WelaProfileCommand configure | Out-Null
    $report = Get-Content -LiteralPath $script:ResultsPath -Raw | ConvertFrom-Json
    Assert ($script:writes.Count -eq 0 -and $report.DryRun) 'configure -Profile -DryRun makes no audit writes'
    Assert ($report.Scope -eq 'advanced-audit-policy-only' -and $report.ProfileScope -eq 'advanced-audit-policy-only') 'Profile-only results declare their narrower scope'
    Assert (-not (Test-Path -LiteralPath $script:BackupPath)) 'Profile dry run creates no journal directory'
    Assert ($report.Results.Count -gt 0 -and @($report.Results | Where-Object Status -ne Skipped).Count -eq 0) 'Profile dry-run proposals remain explicit skipped results'

    Reset-Run
    $script:state[$shareGuid] = 1
    $script:concurrentGuid = $processGuid
    Invoke-WelaProfileCommand configure | Out-Null
    $report = Get-Content -LiteralPath $script:ResultsPath -Raw | ConvertFrom-Json
    Assert ($script:state[$shareGuid] -eq 3) 'Minimum Failure preserves existing Success'
    Assert ($script:state[$processGuid] -eq 3) 'Minimum Success preserves concurrently added Failure'
    $processWrite = $script:writes | Where-Object Guid -eq $processGuid
    Assert ($processWrite.Arguments -contains '/success:enable' -and @($processWrite.Arguments | Where-Object { $_ -like '*:disable' }).Count -eq 0) 'Minimum native command only enables required bits'
    Assert ($report.ExitCode -eq 0) 'Minimum supersets pass final compliance verification'
    Assert ($report.Profile -eq 'cis-win11-v4-l1' -and $report.Role -eq 'Client' -and $report.Build -eq 26100) 'Final report retains profile role and build'
    Assert ($report.Version -and $report.SchemaSha256.Length -eq 64 -and $report.Provenance.Count -gt 0) 'Final report retains version and provenance'
    $row = $report.Results | Where-Object { $_.Target.Guid -eq $shareGuid }
    Assert ($row.Mode -eq 'minimum' -and $row.Evidence -and $row.SourceIds.Count -gt 0) 'Per-control mode and source evidence survive the context adapter'
    $journal = @(Get-Content -LiteralPath (Join-Path $script:BackupPath 'before.jsonl') | ConvertFrom-Json)
    Assert (@($journal | Where-Object { $_.Target.Guid -eq $shareGuid -and $_.Before -eq 1 -and $_.Desired.Mask -eq 2 -and $_.Desired.Mode -eq 'minimum' }).Count -eq 1) 'Minimum policy journal preserves before state and requirement semantics'

    Reset-Run 'microsoft-sct-win11-24h2'
    $script:state[$privilegeGuid] = 3
    Invoke-WelaProfileCommand configure | Out-Null
    Assert ($script:state[$privilegeGuid] -eq 1) 'Exact SCT mask remains exact rather than hardcoded SF'
    $privilegeWrite = $script:writes | Where-Object Guid -eq $privilegeGuid
    Assert ($privilegeWrite.Arguments -contains '/failure:disable') 'Exact Success deliberately clears unrequested Failure'

    Reset-Run 'wela-2.2.0'
    $script:IncludeOptional = $true
    Invoke-WelaProfileCommand configure | Out-Null
    $report = Get-Content -LiteralPath $script:ResultsPath -Raw | ConvertFrom-Json
    $kernel = $report.Results | Where-Object Id -eq 'AuditPolicy/Kernel Object'
    Assert ($kernel.Prerequisites -match 'SACL' -and $kernel.Evidence -and $kernel.SourceIds.Count -gt 0) 'Added native controls retain dependency and source evidence after apply'

    Reset-Run
    $script:failGuid = $processGuid
    Assert-Throws { Invoke-WelaProfileCommand configure } 'advanced audit policies failed'
    $report = Get-Content -LiteralPath $script:ResultsPath -Raw | ConvertFrom-Json
    Assert ($report.ExitCode -eq 1 -and $report.Failed -eq 1) 'Profile native failure reaches final machine-readable result'
    Assert ($script:writes.Count -gt 0) 'Other policy controls continue after one failure'

    Reset-Run 'windows-defaults-reviewed-2026-09'
    Assert-Throws { Invoke-WelaProfileCommand configure } 'reference'
    Assert ($script:writes.Count -eq 0 -and -not (Test-Path -LiteralPath $script:BackupPath)) 'Reference-only defaults fail before journal creation or mutation'

    Reset-Run
    $script:state.Remove($processGuid)
    Assert-Throws { Invoke-WelaProfileCommand configure } 'unknown current'
    Assert ($script:writes.Count -eq 0 -and -not (Test-Path -LiteralPath $script:BackupPath)) 'Missing required state refuses the entire profile before mutation'

    Reset-Run
    $script:hostBuild = 19045
    Assert-Throws { ConfigureAuditSettings -Auto -BackupPath $script:BackupPath } 'does not support'
    Assert ($script:writes.Count -eq 0 -and -not (Test-Path -LiteralPath $script:BackupPath)) 'Legacy configure rejects unsupported hosts before any control or journal'
    $referencePlan = Get-WelaAuditProfilePlan -Profile wela-2.2.0 -Role Client -Build 26100 -Current $zero
    $emptyContext = New-WelaConfigurationContext -DryRun
    $broaderReport = Complete-WelaConfiguration -Context $emptyContext -Plan $referencePlan
    Assert ($broaderReport.Scope -eq 'native-windows-configuration' -and $broaderReport.ProfileScope -eq 'advanced-audit-policy-only') 'Broad configure scope is not mislabeled as its audit-policy profile scope'
    $engine = (Get-Process -Id $PID).Path
    $helpOutput = & $engine -NoProfile -File (Join-Path $repo 'WELA.ps1') configure -Profile cis-win11-v4-l1 -Help 2>&1
    Assert ($LASTEXITCODE -eq 0 -and ($helpOutput -join ' ') -match 'Usage:.*-Profile') 'Profile configure help returns usage without entering the Windows mutation path'
    Write-Host "PASS: $script:assertions profile configuration integration assertions (mocked; no Windows changes)."
} finally {
    foreach ($path in $script:cleanup) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
    }
}
