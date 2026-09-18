# Safety regressions use extracted dispatcher statements with stub mutators and mocked registry APIs.
# Never dot-source WELA or invoke configure-sacl/update-rules implementations from this test.
$ErrorActionPreference = 'Stop'
# Keep mocks in the same script scope as dot-sourced helpers/imported commands;
# Windows PowerShell 5.1 resolves script-local originals ahead of global mocks.
$repo = Split-Path $PSScriptRoot -Parent
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'WELA.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
$dispatch = $ast.Find({ param($node) $node -is [Management.Automation.Language.SwitchStatementAst] -and $node.Condition.Extent.Text -eq '$Cmd.ToLower()' }, $false)
$guard = $ast.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.IfStatementAst] -and $_.Extent.Text -match '-DryRun is supported only by configure'
} | Select-Object -First 1
if (-not $guard -or $guard.Extent.StartOffset -ge $dispatch.Extent.StartOffset) { throw 'DryRun rejection guard must precede command dispatch.' }
$source = Get-Content -LiteralPath (Join-Path $repo 'WELA.ps1') -Raw
$dispatchOnly = [scriptblock]::Create($source.Substring($guard.Extent.StartOffset, $dispatch.Extent.EndOffset - $guard.Extent.StartOffset))
$script:assertions = 0
function Assert($Condition, [string]$Message) {
    if (-not $Condition) { throw "FAIL: $Message" }
    $script:assertions++
}
# These stubs are the only mutators visible to the extracted command dispatcher.
function Set-AuditSacl { param([switch]$Auto) $script:saclCalls++ }
function UpdateRules { $script:updateCalls++ }
function ConfigureAuditSettings { $script:configureCalls++; [pscustomobject]@{ ExitCode = 0 } }
function Invoke-WelaProfileCommand { param($Command) $script:profileCalls++ }
$Help = $false; $Auto = $true; $Baseline = $null; $Profile = $null; $Debug = $false
$BackupPath = $null; $ResultsPath = $null; $OutgoingNtlmMode = 'PreserveOrAudit'
foreach ($command in @('configure-sacl', 'update-rules')) {
    $Cmd = $command; $DryRun = $true
    $script:saclCalls = 0; $script:updateCalls = 0
    $caught = ''
    try { & $dispatchOnly | Out-Null } catch { $caught = $_.ToString() }
    Assert ($caught -match '-DryRun is supported only by configure') "Unsupported DryRun for $command is rejected"
    Assert ($script:saclCalls -eq 0 -and $script:updateCalls -eq 0) "DryRun rejection occurs before $command mutator"
    $DryRun = $false
    & $dispatchOnly | Out-Null
    Assert (($script:saclCalls + $script:updateCalls) -eq 1) "Safe fixture would detect dispatch to $command without the guard"
}
$Cmd = 'configure'; $DryRun = $true; $script:configureCalls = 0
& $dispatchOnly | Out-Null
Assert ($script:configureCalls -eq 1) 'Supported configure DryRun still dispatches'
$Profile = 'wela-2.2.0'; $script:profileCalls = 0
& $dispatchOnly | Out-Null
Assert ($script:profileCalls -eq 1) 'Supported profile DryRun still dispatches'

. (Join-Path $repo 'scripts/Configuration.ps1')
$script:cleanup = New-Object 'System.Collections.Generic.List[string]'
function Reset-Race($Value = 0, [string]$Type = 'DWord') {
    $script:value = $Value; $script:type = $Type
    $script:writes = 0; $script:changeOnPrompt = $null; $script:changeAfterJournal = $null
    $script:prewriteReadFails = $false; $script:journalWritten = $false
}
function New-RaceContext([switch]$Prompt) {
    $path = Join-Path ([IO.Path]::GetTempPath()) ('wela-safety-' + [guid]::NewGuid().ToString('N'))
    $script:cleanup.Add($path)
    New-WelaConfigurationContext -Auto:(-not $Prompt) -BackupPath $path
}
function Get-WelaOutgoingNtlmState {
    # The first display is deliberately stale; the shared runner must trust its own fresh read.
    [pscustomobject]@{ Readable = $true; Value = 0; Description = 'Allow all (initial read)'; PolicySource = 'mock' }
}
function Get-WelaRegistryState {
    param($Path, $Name)
    if ($script:journalWritten -and $script:prewriteReadFails) { throw 'Mock prewrite read failure' }
    [pscustomobject]@{ KeyExists = $true; ValueExists = $true; Value = $script:value; Type = $script:type }
}
function New-WelaRegistryKey { param($Path) }
function Set-ItemProperty {
    param($LiteralPath, $Name, $Value, $Type, $ErrorAction)
    $script:value = $Value; $script:type = $Type; $script:writes++
}
function Read-Host {
    param($Prompt)
    if ($null -ne $script:changeOnPrompt) { $script:value = $script:changeOnPrompt }
    return 'Y'
}
function Add-Content {
    param($LiteralPath, $Value, $Encoding, $ErrorAction)
    process {
        # Preserve real temporary recovery files; only the mocked policy state changes.
        $text = if ($PSBoundParameters.ContainsKey('Value')) { $Value } else { $_ }
        Microsoft.PowerShell.Management\Add-Content -LiteralPath $LiteralPath -Value $text -Encoding $Encoding -ErrorAction Stop
        $script:journalWritten = $true
        if ($null -ne $script:changeAfterJournal) { $script:value = $script:changeAfterJournal }
    }
}
try {
    foreach ($value in @(2, 42)) {
        Reset-Race $value
        $context = New-RaceContext
        Set-WelaNtlmConfigurationControl -Context $context -Scope Outgoing -Mode PreserveOrAudit
        Assert ($script:writes -eq 0 -and $script:value -eq $value) "Fresh Before value $value is preserved despite stale display"
        Assert ($context.Results[0].Status -eq 'Skipped' -and $context.Results[0].Before.Value -eq $value) 'Preservation records actual fresh snapshot'
        Assert (-not $script:journalWritten) 'Initially preserved value produces no mutation journal'
    }
    Reset-Race 0 String
    $context = New-RaceContext
    Set-WelaNtlmConfigurationControl -Context $context -Scope Outgoing
    Assert ($script:writes -eq 0 -and $context.Results[0].Status -eq 'Skipped') 'Unknown registry type is preserved by default'

    foreach ($changed in @(2, 42)) {
        Reset-Race
        $script:changeOnPrompt = $changed
        $context = New-RaceContext -Prompt
        Set-WelaNtlmConfigurationControl -Context $context -Scope Outgoing
        Assert ($script:writes -eq 0 -and $script:value -eq $changed) "New value $changed introduced while prompting is never overwritten"
        Assert ($context.Results[0].Status -eq 'Failed' -and $context.Results[0].Diagnostic -match 'Refused registry write') 'Changed policy is refused and reported for operator review'
    }
    foreach ($changed in @(2, 42)) {
        Reset-Race
        $script:changeAfterJournal = $changed
        $context = New-RaceContext
        Set-WelaNtlmConfigurationControl -Context $context -Scope Outgoing
        Assert ($script:writes -eq 0 -and $script:value -eq $changed) "New value $changed introduced after journaling is preserved"
        Assert ($context.Results[0].Status -eq 'Failed') 'Prewrite refusal contributes to overall failure'
    }
    Reset-Race
    $script:prewriteReadFails = $true
    $context = New-RaceContext
    Set-WelaNtlmConfigurationControl -Context $context -Scope Outgoing
    Assert ($script:writes -eq 0 -and $context.Results[0].Status -eq 'Failed') 'Unreadable prewrite policy prevents mutation'

    Reset-Race 2
    $context = New-RaceContext
    Set-WelaNtlmConfigurationControl -Context $context -Scope Outgoing -Mode Audit
    Assert ($script:writes -eq 1 -and $script:value -eq 1) 'Explicit Audit still overrides fresh deny intentionally'
    Assert ($context.Results[0].Status -eq 'Applied') 'Explicit override requires successful verification'
    Write-Host "PASS: $script:assertions integration safety assertions (stub dispatcher and registry; no Windows changes)."
} finally {
    foreach ($path in $script:cleanup) {
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
    }
}
