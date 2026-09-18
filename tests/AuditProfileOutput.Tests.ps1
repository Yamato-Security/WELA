# Exercise the real profile, audit renderer, rule coverage and CSV output with
# injected audit observations. Only temporary files are written; no Windows policy changes.
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../modules/AuditProfiles.psm1') -Force
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../WELA.ps1'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$class = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.TypeDefinitionAst] -and $node.Name -eq 'WELA' }, $true)
. ([scriptblock]::Create($class.Extent.Text))
foreach ($name in @('ApplyRules', 'BuildAuditResult', 'AuditLogSetting')) {
    $definition = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    . ([scriptblock]::Create($definition.Extent.Text))
}

$script:assertions = 0
function Assert-Equal($Actual, $Expected, [string]$Message) {
    if ($Actual -cne $Expected) { throw "$Message. Expected '$Expected', got '$Actual'." }
    $script:assertions++
}
function TestAdministrator { return $true }
function CollectAuditpol { param([switch]$UseCached) return $true }
function GetAuditpol { return $script:observedAudit }
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

    foreach ($role in @('Client', 'MemberServer', 'DomainController', 'ADCS')) {
        foreach ($observed in @('Success', 'No Auditing', 'Missing')) {
            $script:observedRole = $role
            $script:observedAudit = @{}
            foreach ($policy in $catalog) { $script:observedAudit[$policy.guid] = 'No Auditing' }
            foreach ($name in @('Directory Service Changes', 'Kerberos Authentication Service', 'Certification Services')) {
                if ($observed -eq 'Missing') { $script:observedAudit.Remove($guids[$name]) }
                else { $script:observedAudit[$guids[$name]] = $observed }
            }
            $script:observedAudit[$guids['Kernel Object']] = 'Success'
            $script:observedAudit[$fallbackGuid] = 'Success'

            $output = AuditLogSetting -outType std -Baseline YamatoSecurity 6>&1 | Out-String
            $rows = @(Import-Csv -LiteralPath (Join-Path $script:ScriptRoot 'WELA-Audit-Result.csv'))
            foreach ($name in @('Directory Service Changes', 'Kerberos Authentication Service', 'Certification Services')) {
                $policy = $catalog | Where-Object id -eq $name
                $row = @($rows | Where-Object SubCategory -eq $name)
                $expectedState = if ($role -notin $policy.roles) { 'Not applicable' }
                                 elseif ($observed -eq 'Missing') { 'Unknown' }
                                 else { $observed }
                Assert-Equal $row.Count 1 "$role/$observed contains exactly one $name CSV row"
                Assert-Equal $row[0].CurrentSetting $expectedState "$role/$observed $name uses role applicability before the live state"
                $expectedRuleCount = if ($name -eq 'Directory Service Changes') { '2' } else { '1' }
                Assert-Equal $row[0].RuleCount $expectedRuleCount "$role/$observed retains mapped rules for $name without dropping them from the corpus"
            }

            if ($role -ne 'DomainController') {
                Assert-Equal ($output -match '(?m)^Security Advanced \(DS Access\): Not applicable\r?$') $true "$role/$observed all-inapplicable category has no enabled percentage"
                Assert-Equal ($output -match '(?m)^Security Advanced \(Account Logon\): Disabled\(0[.,]00%\)\r?$') $true "$role/$observed excludes DC-only rows from mixed category totals"
            }
            if ($role -ne 'ADCS') {
                Assert-Equal ($output -match '(?m)^Security Advanced \(Object Access\): Enabled\(100[.,]00%\)\r?$') $true "$role/$observed excludes the CA-only row from enabled category coverage"
            }

            $usable = @(Import-Csv -LiteralPath (Join-Path $script:ScriptRoot 'UsableRules.csv'))
            $unusable = @(Import-Csv -LiteralPath (Join-Path $script:ScriptRoot 'UnusableRules.csv'))
            $expectedUsable = 3
            if ($observed -eq 'Success' -and $role -eq 'DomainController') { $expectedUsable += 2 }
            if ($observed -eq 'Success' -and $role -eq 'ADCS') { $expectedUsable++ }
            Assert-Equal $usable.Count $expectedUsable "$role/$observed does not rescue role-inapplicable GUIDs as usable"
            Assert-Equal ($usable.Count + $unusable.Count) 8 "$role/$observed retains all unique rules in the utilization denominator"
            Assert-Equal ($usable.id -contains 'alternative') $true "$role/$observed permits an applicable alternative source"
            Assert-Equal ($usable.id -contains 'fallback') $true "$role/$observed still rescues an enabled GUID outside the catalog"
            Assert-Equal ($usable.id -contains 'unknown') $false "$role/$observed leaves an unknown source unavailable"
            $expectedUtilization = 'You can utilize {0:N2}% of your detection rules.' -f ($expectedUsable / 8 * 100)
            Assert-Equal ($output.Contains($expectedUtilization)) $true "$role/$observed reports utilization from the complete deduplicated corpus"
            foreach ($ruleId in @('directory', 'kerberos', 'ca')) {
                $rule = $script:heatmapRules | Where-Object id -eq $ruleId
                $applicableRole = if ($ruleId -eq 'ca') { 'ADCS' } else { 'DomainController' }
                if ($role -ne $applicableRole) {
                    Assert-Equal $rule.applicable $false "$role/$observed excludes $ruleId from current heatmap coverage"
                    Assert-Equal $rule.ideal $false "$role/$observed excludes $ruleId from ideal heatmap coverage"
                }
            }
        }
    }
    Write-Host "PASS: $script:assertions audit profile output assertions (mocked observations; temporary CSV files only)."
} finally {
    Remove-Item -LiteralPath $script:ScriptRoot -Recurse -Force
}
