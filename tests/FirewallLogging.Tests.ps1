$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$script:ScriptRoot = $repo
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/FirewallLogging.ps1')
$script:assertions = 0
$script:paths = @()
function Assert($Condition, [string]$Message) {
    if (-not $Condition) { throw "FAIL: $Message" }
    $script:assertions++
}
function New-Entry($Name, $Size = 4096) {
    [pscustomobject]@{ Name = $Name; LogAllowed = 'False'; LogBlocked = 'False'; LogMaxSizeKilobytes = $Size; LogFileName = "C:\Operator\$Name.log"; Enabled = 'False' }
}
function Reset-Mocks {
    $script:localProfiles = @{}; $script:effectiveProfiles = @{}
    foreach ($name in @('Domain', 'Private', 'Public')) {
        $script:localProfiles[$name] = New-Entry $name
        $script:effectiveProfiles[$name] = New-Entry $name
    }
    $script:writes = 0; $script:writeArguments = @(); $script:blockedAccess = $false
    $script:failRead = $false; $script:failWrite = $false; $script:gpo = $false; $script:onPrompt = $null
    $script:accessCalls = 0
}
function Get-NetFirewallProfile {
    param($Name, $PolicyStore, $ErrorAction)
    if ($script:failRead) { throw 'Read denied' }
    if ($PolicyStore -eq 'ActiveStore') { return $script:effectiveProfiles[$Name] }
    if ($PolicyStore -eq 'PersistentStore') { return $script:localProfiles[$Name] }
    throw "Unexpected store $PolicyStore"
}
function Set-NetFirewallProfile {
    param($Name, $PolicyStore, $LogAllowed, $LogBlocked, $LogMaxSizeKilobytes, $LogFileName, $ErrorAction)
    Assert ($PolicyStore -eq 'PersistentStore') 'Only local persistent policy is written'
    $entries = @(Get-Content -LiteralPath (Join-Path $script:context.BackupPath 'before.jsonl') | ConvertFrom-Json)
    Assert ($entries[-1].Target.Name -eq $Name) 'Matching recovery snapshot exists before each write'
    Assert ($entries[-1].Before.Local.Name -eq $Name -and $entries[-1].Before.Effective.Name -eq $Name) 'Journal includes local and effective snapshots'
    if ($script:failWrite) { throw 'Mock policy write failed' }
    $script:writes++
    $script:writeArguments += $PSBoundParameters
    foreach ($store in @($script:localProfiles, $script:effectiveProfiles)) {
        if ($script:gpo -and [object]::ReferenceEquals($store, $script:effectiveProfiles)) { continue }
        $store[$Name].LogAllowed = $LogAllowed; $store[$Name].LogBlocked = $LogBlocked; $store[$Name].LogMaxSizeKilobytes = $LogMaxSizeKilobytes
        if ($PSBoundParameters.ContainsKey('LogFileName')) { $store[$Name].LogFileName = $LogFileName }
    }
}
function Get-WelaFirewallLogAccess {
    param($Path)
    $script:accessCalls++
    [pscustomobject]@{ State = $(if ($script:blockedAccess) { 'Unknown' } else { 'VerifiedExplicitGrant' }); Path = $Path; Diagnostic = 'Mock service ACL'; ServiceAccount = 'NT AUTHORITY\LocalService'; ServiceStatus = 'Running' }
}
function Read-Host {
    param($Prompt)
    if ($script:onPrompt) { & $script:onPrompt }
    'Y'
}
function New-TestContext([switch]$DryRun, [switch]$Prompt) {
    $path = Join-Path ([IO.Path]::GetTempPath()) ('wela-firewall-' + [guid]::NewGuid().ToString('N'))
    $script:paths += $path
    $script:context = New-WelaConfigurationContext -Auto:(-not $Prompt) -DryRun:$DryRun -BackupPath $path
    return $script:context
}
function New-Ace($Sid, $Rights, $Inheritance = 'ObjectInherit', $Propagation = 'None', $Type = 'Allow') {
    [pscustomobject]@{ IdentityReference = [pscustomobject]@{ Value = $Sid }; FileSystemRights = [Security.AccessControl.FileSystemRights]$Rights; InheritanceFlags = [Security.AccessControl.InheritanceFlags]$Inheritance; PropagationFlags = [Security.AccessControl.PropagationFlags]$Propagation; AccessControlType = $Type }
}
try {
    $sid = 'S-1-5-80-123'
    $good = New-Ace $sid 'Modify'
    Assert (Test-WelaFirewallServiceAcl @($good) $sid -Directory) 'Service Modify grant covers directory creation/rotation and inherited files'
    Assert (-not (Test-WelaFirewallServiceAcl @((New-Ace $sid 'Read')) $sid -Directory)) 'Read-only service permission is unknown'
    Assert (-not (Test-WelaFirewallServiceAcl @((New-Ace 'S-1-1-0' 'FullControl')) $sid -Directory)) 'Broad group grant is not mistaken for proven service-token access'
    Assert (-not (Test-WelaFirewallServiceAcl @((New-Ace $sid 'Modify' 'None')) $sid -Directory)) 'New log files require inheritable service permission'
    Assert (Test-WelaFirewallServiceAcl @((New-Ace $sid 'Modify' 'None')) $sid) 'Existing file needs self access, not inheritance'
    Assert (-not (Test-WelaFirewallServiceAcl @((New-Ace $sid 'Modify' 'ObjectInherit' 'InheritOnly')) $sid -Directory)) 'Inherit-only grant does not permit directory access'
    Assert (-not (Test-WelaFirewallServiceAcl @($good, (New-Ace 'S-1-1-0' 'Write' 'None' 'None' 'Deny')) $sid -Directory)) 'Any unresolved group deny prevents claiming access'

    Reset-Mocks
    $plan = @(Get-WelaFirewallLoggingPlan)
    Assert ($plan.Count -eq 3 -and ($plan.Name -join ',') -eq 'Domain,Private,Public') 'All profiles are planned'
    Assert (@($plan | Where-Object Status -eq ChangeRequired).Count -eq 3) 'Existing logging gaps are explicit'
    Assert ($plan[0].Desired.MinimumSizeKiB -eq 16384 -and $plan[0].Desired.LogFileName -eq 'C:\Operator\Domain.log') 'Default plan retains operator path and minimum semantics'
    $context = New-TestContext -DryRun
    Set-WelaFirewallLoggingControls $context $plan
    Assert ($script:writes -eq 0 -and $context.Results.Count -eq 3) 'Dry run does not change any profile'
    Assert (-not (Test-Path -LiteralPath $context.BackupPath)) 'Dry run creates no recovery directory'

    Reset-Mocks
    $script:localProfiles.Domain.LogMaxSizeKilobytes = 24576
    $script:effectiveProfiles.Domain.LogMaxSizeKilobytes = 20480
    $context = New-TestContext
    Set-WelaFirewallLoggingControls $context @(Get-WelaFirewallLoggingPlan)
    $result = Complete-WelaConfiguration $context -Scope firewall-text-logging-only
    Assert ($result.ExitCode -eq 0 -and $script:writes -eq 3) 'All three profiles are verified after writing'
    Assert ($script:effectiveProfiles.Domain.LogMaxSizeKilobytes -eq 24576) 'Larger local and effective limits are preserved'
    Assert ($script:effectiveProfiles.Private.LogMaxSizeKilobytes -eq 16384) 'Smaller limit is raised to minimum'
    Assert ($script:effectiveProfiles.Domain.Enabled -eq 'False') 'Disabled firewall enforcement remains untouched'
    Assert (@($script:writeArguments | Where-Object { $_.ContainsKey('LogFileName') }).Count -eq 0) 'Default configuration never writes path parameter'
    $context = New-TestContext
    Set-WelaFirewallLoggingControls $context @(Get-WelaFirewallLoggingPlan)
    Assert ($script:writes -eq 3 -and @($context.Results | Where-Object Status -eq AlreadyCompliant).Count -eq 3) 'Verified settings are idempotent'
    $script:effectiveProfiles.Public.LogAllowed = 'False'
    Assert ((Complete-WelaConfiguration $context).ExitCode -eq 1 -and $context.Results[2].Status -eq 'Overridden') 'Final effective-policy drift fails the run'

    Reset-Mocks
    $context = New-TestContext
    Set-WelaFirewallLoggingControls $context @(Get-WelaFirewallLoggingPlan -PathMode CisV4 -MinimumSizeKiB 20480)
    Assert ($script:writes -eq 3) 'Explicit CIS path configuration writes all profiles'
    foreach ($name in @('Domain', 'Private', 'Public')) {
        Assert ($script:effectiveProfiles[$name].LogFileName -eq ('%SystemRoot%\System32\LogFiles\Firewall\' + $name.ToLowerInvariant() + 'fw.log')) 'Explicit CIS path is distinct for each profile'
    }
    Assert ($script:effectiveProfiles.Public.LogMaxSizeKilobytes -eq 20480) 'Operator can choose the higher Microsoft size recommendation'

    Reset-Mocks
    $script:gpo = $true
    $context = New-TestContext
    Set-WelaFirewallLoggingControls $context @(Get-WelaFirewallLoggingPlan)
    $result = Complete-WelaConfiguration $context
    Assert ($result.ExitCode -eq 1 -and $result.Failed -eq 3) 'Local success with ineffective GPO-overridden settings is failure'
    Assert ($context.Results[0].After.DifferentFromLocal -contains 'LogAllowed') 'Results expose effective versus local differences'

    Reset-Mocks
    $script:blockedAccess = $true
    $plan = @(Get-WelaFirewallLoggingPlan)
    Assert (@($plan | Where-Object Status -eq Unknown).Count -eq 3) 'Unverified service access is Unknown'
    $context = New-TestContext
    Set-WelaFirewallLoggingControls $context $plan
    Assert ($script:writes -eq 0 -and (Complete-WelaConfiguration $context).Failed -eq 3) 'Unknown directory permissions block writes without broadening ACLs'

    Reset-Mocks
    $script:failRead = $true
    $plan = @(Get-WelaFirewallLoggingPlan)
    Assert (@($plan | Where-Object Status -eq Unknown).Count -eq 3) 'Read failure never becomes a configured/default value'
    $context = New-TestContext -DryRun
    Set-WelaFirewallLoggingControls $context $plan
    Assert ($script:writes -eq 0 -and (Complete-WelaConfiguration $context).ExitCode -eq 1) 'Unreadable dry run still reports failure'

    Reset-Mocks
    $script:failWrite = $true
    $context = New-TestContext
    Set-WelaFirewallLoggingControls $context @(Get-WelaFirewallLoggingPlan)
    Assert ((Complete-WelaConfiguration $context).Failed -eq 3) 'Write failures are aggregated and controls continue'

    Reset-Mocks
    $script:onPrompt = { $script:localProfiles.Domain.LogFileName = 'C:\NewOperator\Domain.log' }
    $context = New-TestContext -Prompt
    Set-WelaFirewallLoggingControls $context @((Get-WelaFirewallLoggingPlan)[0])
    Assert ($script:writes -eq 0 -and $context.Results[0].Status -eq 'Failed') 'Operator changes during prompt prevent stale recovery snapshot writes'

    Reset-Mocks
    $plan = @(Get-WelaFirewallLoggingPlan)
    $script:blockedAccess = $true
    $context = New-TestContext -DryRun
    Set-WelaFirewallLoggingControls $context $plan
    Assert ($script:writes -eq 0 -and (Complete-WelaConfiguration $context).Failed -eq 3) 'Permission changes after planning fail even a dry run'

    Reset-Mocks
    $savedOS = $env:OS
    $outputDirectory = Join-Path ([IO.Path]::GetTempPath()) ('wela-firewall-report-' + [guid]::NewGuid().ToString('N'))
    $script:paths += $outputDirectory
    $null = New-Item -ItemType Directory -Path $outputDirectory
    try {
        $env:OS = 'Windows_NT'
        $json = Join-Path $outputDirectory 'plan.json'
        $report = Invoke-WelaFirewallLoggingCommand -Action Plan -ResultsPath $json
        $saved = Get-Content -LiteralPath $json -Raw | ConvertFrom-Json
        Assert ($report.ExitCode -eq 0 -and $saved.Profiles.Count -eq 3 -and $saved.Scope -eq 'firewall-text-logging-only') 'Public plan entrypoint exports all profiles with an explicit scope'
        $dryPath = Join-Path $outputDirectory 'must-not-exist'
        $report = Invoke-WelaFirewallLoggingCommand -Action Configure -DryRun -BackupPath $dryPath -ResultsPath $json
        Assert ($report.DryRun -and $report.ExitCode -eq 0 -and $script:writes -eq 0 -and -not (Test-Path $dryPath)) 'Public configure entrypoint propagates dry run and results scope'
        $rejected = $false
        try { Invoke-WelaFirewallLoggingCommand -Action Audit -DryRun } catch { $rejected = $true }
        Assert $rejected 'Public entrypoint rejects meaningless audit dry-run combinations'
    } finally { $env:OS = $savedOS }

    # Inspect the only writer's AST: no enforcement/rule parameter or ACL mutation may be hidden in a splat.
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'scripts/FirewallLogging.ps1'), [ref]$tokens, [ref]$errors)
    Assert ($errors.Count -eq 0) 'Firewall helper parses'
    Assert (-not ($ast.Extent.Text -match '(?m)^\s*(Set-Acl|New-NetFirewallRule|Set-NetFirewallRule|Start-Service|Restart-Service)\b')) 'Implementation has no ACL/service/enforcement mutator'
    Write-Host "PASS: $script:assertions firewall text logging assertions (mocked; no Windows policy changes)."
} finally {
    foreach ($path in $script:paths) { if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force } }
}
