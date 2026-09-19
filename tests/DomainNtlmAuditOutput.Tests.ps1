# Exercise the real audit renderer/CSV exports with injected observations and rules.
# Only a temporary directory is written; no Windows policy is read or changed.
$ErrorActionPreference = 'Stop'
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../WELA.ps1'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$class = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.TypeDefinitionAst] -and $node.Name -eq 'WELA' }, $true)
. ([scriptblock]::Create($class.Extent.Text))
$definition = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'AuditLogSetting' }, $true)
. ([scriptblock]::Create($definition.Extent.Text))

$script:assertions = 0
function Assert-Equal($Actual, $Expected, [string]$Message) {
    if ($Actual -cne $Expected) { throw "$Message. Expected '$Expected', got '$Actual'." }
    $script:assertions++
}
function TestAdministrator { return $true }
function CollectAuditpol { param([switch]$UseCached) return $true }
function GetAuditpol { return @{} }
function Get-WelaOutgoingNtlmState {
    return [pscustomobject]@{ Description = 'Audit all (1)'; PolicySource = 'Mocked policy source' }
}
function Get-WelaDomainNtlmState { return [pscustomobject]@{ Description = $script:description } }
function Export-MitreHeatmap { param($sigmaRules, $OutputPath, $UseIdealCount) }
function BuildAuditResult {
    param($all_rules, $Baseline, $enabledguid)
    $all_rules[0].applicable = $true
    @(
        [WELA]::new('Fixture rules', 'Available', 'Success', @($all_rules[0]))
        [WELA]::new('Fixture rules', 'Unavailable', 'No Auditing', @($all_rules[1]))
    )
}

$script:ScriptRoot = Join-Path ([IO.Path]::GetTempPath()) ('wela-domain-output-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $script:ScriptRoot
$script:SecurityRulesPath = Join-Path $script:ScriptRoot 'rules.json'
try {
    @(
        @{ id = 'available-rule'; title = 'Available fixture'; level = 'high'; subcategory_guids = @() }
        @{ id = 'unavailable-rule'; title = 'Unavailable fixture'; level = 'medium'; subcategory_guids = @() }
    ) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $script:SecurityRulesPath -Encoding UTF8
    foreach ($observed in @(
        'Enable all (7)',
        'Disabled (0)',
        'Not configured',
        'Value 2 (not interpreted as Enable all)',
        'Not applicable (Windows client)',
        'Not applicable (member or standalone server, including non-DC AD CS)',
        'Unknown (computer role could not be determined)',
        'Unknown (domain NTLM registry read failed: Access denied)'
    )) {
        $script:description = $observed
        $output = (AuditLogSetting -outType std -Baseline YamatoSecurity 6>&1 | Out-String)
        $expectedHeading = 'NTLM Authentication: Audit all (1); ' + $observed
        Assert-Equal ($output -match ('(?m)^' + [regex]::Escape($expectedHeading) + '\r?$')) $true "Console heading retains '$observed'"
        Assert-Equal ($output -match 'NTLM Authentication: Partially Enabled') $false 'An empty rule array does not imply partial enablement'
        Assert-Equal ($output -match 'Fixture rules: Partially Enabled') $true 'Ordinary rule coverage aggregation is preserved'
        $row = @(Import-Csv -LiteralPath (Join-Path $script:ScriptRoot 'WELA-Audit-Result.csv') | Where-Object SubCategory -eq 'Domain NTLM auditing')
        Assert-Equal $row.Count 1 'CSV contains one domain NTLM setting row'
        Assert-Equal $row[0].CurrentSetting $observed 'CSV retains the observed configuration state'
        Assert-Equal $row[0].RuleCount '0' 'Configuration row claims no detection rules'
        $outgoingRow = @(Import-Csv -LiteralPath (Join-Path $script:ScriptRoot 'WELA-Audit-Result.csv') | Where-Object SubCategory -eq 'Outgoing NTLM policy')
        Assert-Equal $outgoingRow.Count 1 'CSV contains one outgoing NTLM setting row'
        Assert-Equal $outgoingRow[0].CurrentSetting 'Audit all (1)' 'CSV retains the independent outgoing NTLM state'
        Assert-Equal $outgoingRow[0].RuleCount '0' 'Outgoing configuration row claims no detection rules'
        Assert-Equal @(Import-Csv -LiteralPath (Join-Path $script:ScriptRoot 'UsableRules.csv')).Count 1 'Configuration row does not change usable rule counts'
        Assert-Equal @(Import-Csv -LiteralPath (Join-Path $script:ScriptRoot 'UnusableRules.csv')).Count 1 'Configuration row does not change unusable rule counts'
    }
    Write-Host "PASS: $script:assertions domain NTLM output assertions (mocked observations; temporary CSV files only)."
} finally {
    Remove-Item -LiteralPath $script:ScriptRoot -Recurse -Force
}
