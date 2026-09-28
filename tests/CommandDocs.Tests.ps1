$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$count = 0
function Assert($Value, [string] $Message) {
    if (-not $Value) { throw $Message }
    $script:count++
}

$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $repo 'WELA.ps1'),
    [ref] $tokens,
    [ref] $errors
)
Assert ($errors.Count -eq 0) 'WELA.ps1 must parse before its dispatch table can be checked.'

$dispatches = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.SwitchStatementAst] -and
        $node.Condition.Extent.Text -eq '$Cmd.ToLower()'
}, $true))
Assert ($dispatches.Count -eq 1) "Expected one public command dispatch switch; found $($dispatches.Count)."

$implemented = [System.Collections.Generic.List[string]]::new()
foreach ($clause in $dispatches[0].Clauses) {
    $label = $clause.Item1
    if ($label -is [Management.Automation.Language.StringConstantExpressionAst]) {
        $implemented.Add($label.Value)
        continue
    }
    foreach ($match in [regex]::Matches($label.Extent.Text, '[''"](?<name>[a-z0-9-]+)[''"]')) {
        $implemented.Add($match.Groups['name'].Value)
    }
}
$implemented = @($implemented | Sort-Object -Unique)
Assert ($implemented.Count -gt 0) 'The public dispatch table must contain commands.'

function Get-DocumentedCommands([string] $Path) {
    $content = Get-Content -LiteralPath $Path -Raw
    $matches = @([regex]::Matches($content, '(?m)^\|\s+`(?<name>[a-z0-9-]+)`\s+\|'))
    $names = @($matches | ForEach-Object { $_.Groups['name'].Value })
    Assert ($names.Count -eq @($names | Sort-Object -Unique).Count) "$Path contains a duplicate command row."
    return @($names | Sort-Object -Unique)
}

foreach ($relative in @('website/docs/commands/index.md', 'website/docs/commands/index.ja.md')) {
    $path = Join-Path $repo $relative
    $documented = Get-DocumentedCommands $path
    $difference = @(Compare-Object -ReferenceObject $implemented -DifferenceObject $documented)
    Assert ($difference.Count -eq 0) "$relative is out of sync with WELA.ps1: $($difference | Out-String)"
}

$usageEn = Get-Content -LiteralPath (Join-Path $repo 'website/docs/commands/usage.md') -Raw
$usageJa = Get-Content -LiteralPath (Join-Path $repo 'website/docs/commands/usage.ja.md') -Raw
Assert ($usageEn -notmatch '(?i)configure\s+-Baseline\s+ASD') 'English usage must not recommend the rejected configure ASD baseline.'
Assert ($usageJa -notmatch '(?i)configure\s+-Baseline\s+ASD') 'Japanese usage must not recommend the rejected configure ASD baseline.'
Assert ($usageJa -notmatch '(?i)audit-filesize\s+-Baseline') 'Japanese usage must use event-log profiles for audit-filesize.'

$mkdocs = Get-Content -LiteralPath (Join-Path $repo 'website/mkdocs.yml') -Raw
Assert ($mkdocs -match 'commands/native-audit-controls\.md') 'MkDocs navigation must expose the native audit controls page.'
Assert (Test-Path -LiteralPath (Join-Path $repo 'website/docs/commands/native-audit-controls.ja.md') -PathType Leaf) 'The native audit controls page needs a Japanese counterpart.'

Write-Host "PASS: $count command documentation assertions for $($implemented.Count) public commands."
$global:LASTEXITCODE = 0
