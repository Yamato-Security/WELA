# Exercise the real profile, audit renderer, rule coverage and CSV output with
# injected audit observations. Only temporary files are written; no Windows policy changes.
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../modules/RuleEligibility.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../modules/AuditCatalog.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../modules/AuditProfiles.psm1') -Force
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../WELA.ps1'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$class = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.TypeDefinitionAst] -and $node.Name -eq 'WELA' }, $true)
. ([scriptblock]::Create($class.Extent.Text))
foreach ($name in @('ApplyRules', 'Get-WelaObservedAuditMask', 'BuildAuditResult', 'AuditLogSetting')) {
    $definition = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    . ([scriptblock]::Create($definition.Extent.Text))
}

$script:assertions = 0
function Assert-Equal($Actual, $Expected, [string]$Message) {
    if ($Actual -cne $Expected) { throw "$Message. Expected '$Expected', got '$Actual'." }
    $script:assertions++
}
function TestAdministrator { return $true }
function Get-WelaEffectiveAuditPolicy { return $script:observedAudit }
function Get-WelaSelectedContext { return [pscustomobject]@{ Role = $script:observedRole; Build = 26100 } }
function GetBaselineConfig {
    # Advanced audit policies still come from the actual versioned profile.
    return [pscustomobject]@{ baselines = [pscustomobject]@{ YamatoSecurity = [pscustomobject]@{} }; catalog = @() }
}
function Get-WelaOutgoingNtlmState { return [pscustomobject]@{ Description = 'Audit all (1)'; PolicySource = 'Test observation' } }
function Get-WelaDomainNtlmState { return [pscustomobject]@{ Description = 'Test observation' } }
function Export-MitreHeatmap {
    param($sigmaRules, $OutputPath, $UseIdealCount)
    $script:heatmapRules = @($sigmaRules)
}

$catalog = (Import-WelaAuditProfiles).catalog
$guids = @{}
foreach ($policy in $catalog) { $guids[$policy.id] = $policy.guid }
$fallbackGuid = '00000000-0000-0000-0000-000000000001'
$script:ScriptRoot = Join-Path ([IO.Path]::GetTempPath()) ('wela-profile-output-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $script:ScriptRoot
$script:SecurityRulesPath = Join-Path $script:ScriptRoot 'rules.json'
try {
    @(
        @{ id = 'directory'; title = 'DC-only rule'; level = 'high'; subcategory_guids = @($guids['Directory Service Changes']) }
        @{ id = 'kerberos'; title = 'DC-only rule in a mixed category'; level = 'high'; subcategory_guids = @($guids['Kerberos Authentication Service']) }
        @{ id = 'credential'; title = 'Disabled rule in a mixed category'; level = 'medium'; subcategory_guids = @($guids['Credential Validation']) }
        @{ id = 'ca'; title = 'CA-only rule'; level = 'medium'; subcategory_guids = @($guids['Certification Services']) }
        @{ id = 'kernel'; title = 'Enabled applicable rule'; level = 'medium'; subcategory_guids = @($guids['Kernel Object']) }
        @{ id = 'alternative'; title = 'Applicable alternative log source'; level = 'medium'; subcategory_guids = @($guids['Directory Service Changes'], $guids['Kernel Object']) }
        @{ id = 'fallback'; title = 'Enabled policy outside the catalog'; level = 'low'; subcategory_guids = @($fallbackGuid) }
        @{ id = 'unknown'; title = 'Uncategorized rule'; level = 'low'; subcategory_guids = @() }
    ) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $script:SecurityRulesPath -Encoding UTF8

    $cases = @(
        [pscustomobject]@{ Name = 'Success'; Present = $true; Mask = 1; Current = 'Success' }
        [pscustomobject]@{ Name = 'No Auditing'; Present = $true; Mask = 0; Current = 'No Auditing' }
        [pscustomobject]@{ Name = 'Missing'; Present = $false; Mask = $null; Current = 'Unknown' }
    )
    foreach ($role in @('Client', 'MemberServer', 'DomainController', 'ADCS')) {
        foreach ($case in $cases) {
            $script:observedRole = $role
            $script:observedAudit = @{}
            foreach ($policy in $catalog) { $script:observedAudit[$policy.guid] = 0 }
            foreach ($name in @('Directory Service Changes', 'Kerberos Authentication Service', 'Certification Services')) {
                if (-not $case.Present) { $script:observedAudit.Remove($guids[$name]) }
                else { $script:observedAudit[$guids[$name]] = $case.Mask }
            }
            $script:observedAudit[$guids['Kernel Object']] = 1
            $script:observedAudit[$fallbackGuid] = 1

            $output = AuditLogSetting -outType std -Baseline YamatoSecurity 6>&1 | Out-String
            $rows = @(Import-Csv -LiteralPath (Join-Path $script:ScriptRoot 'WELA-Audit-Result.csv'))
            foreach ($name in @('Directory Service Changes', 'Kerberos Authentication Service', 'Certification Services')) {
                $policy = $catalog | Where-Object id -eq $name
                $row = @($rows | Where-Object SubCategory -eq $name)
                $expectedState = if ($role -notin $policy.roles) { 'Not applicable' }
                                 else { $case.Current }
                $expectedMask = if ($case.Present) { [string]$case.Mask } else { '' }
                Assert-Equal $row.Count 1 "$role/$($case.Name) contains exactly one $name CSV row"
                Assert-Equal $row[0].CurrentSetting $expectedState "$role/$($case.Name) $name uses role applicability before the live state"
                Assert-Equal $row[0].AuditPolicyMask $expectedMask "$role/$($case.Name) $name exports the locale-independent mask"
                $expectedRuleCount = if ($name -eq 'Directory Service Changes') { '2' } else { '1' }
                Assert-Equal $row[0].RuleCount $expectedRuleCount "$role/$($case.Name) retains mapped rules for $name without dropping them from the corpus"
            }

            if ($role -ne 'DomainController') {
                Assert-Equal ($output -match '(?m)^Security Advanced \(DS Access\): Not applicable\r?$') $true "$role/$($case.Name) all-inapplicable category has no enabled percentage"
                Assert-Equal ($output -match '(?m)^Security Advanced \(Account Logon\): Disabled\(0[.,]00%\)\r?$') $true "$role/$($case.Name) excludes DC-only rows from mixed category totals"
            }
            if ($role -ne 'ADCS') {
                Assert-Equal ($output -match '(?m)^Security Advanced \(Object Access\): Enabled\(100[.,]00%\)\r?$') $true "$role/$($case.Name) excludes the CA-only row from enabled category coverage"
            }

            $usable = @(Import-Csv -LiteralPath (Join-Path $script:ScriptRoot 'UsableRules.csv'))
            $unusable = @(Import-Csv -LiteralPath (Join-Path $script:ScriptRoot 'UnusableRules.csv'))
            Assert-Equal $usable.Count 0 "$role/$($case.Name) enabled policy alone never establishes usable rules"
            Assert-Equal ($usable.Count + $unusable.Count) 8 "$role/$($case.Name) retains all unique rules in the corpus"
            $eligibility = @(Import-Csv -LiteralPath (Join-Path $script:ScriptRoot 'RuleEligibility.csv'))
            Assert-Equal $eligibility.Count 8 "$role/$($case.Name) exports a reason for every rule"
            Assert-Equal @($eligibility | Where-Object { $_.State -eq 'Ready' }).Count 0 "$role/$($case.Name) supplies no event/query evidence"
            Assert-Equal ($output.Contains('Evidence-qualified Ready: 0/8 native candidates (0.00% of all 8 unique input rules).') -or $output.Contains('Evidence-qualified Ready: 0/8 native candidates (0,00% of all 8 unique input rules).')) $true "$role/$($case.Name) states the explicit numerator and denominator"
            foreach ($ruleId in @('directory', 'kerberos', 'ca')) {
                $rule = $script:heatmapRules | Where-Object id -eq $ruleId
                $applicableRole = if ($ruleId -eq 'ca') { 'ADCS' } else { 'DomainController' }
                if ($role -ne $applicableRole) {
                    Assert-Equal $rule.applicable $false "$role/$($case.Name) excludes $ruleId from current heatmap coverage"
                    Assert-Equal $rule.ideal $false "$role/$($case.Name) excludes $ruleId from ideal heatmap coverage"
                }
            }
        }
    }
    Write-Host "PASS: $script:assertions audit profile output assertions (mocked observations; temporary CSV files only)."
} finally {
    Remove-Item -LiteralPath $script:ScriptRoot -Recurse -Force
}
