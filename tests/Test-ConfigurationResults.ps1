# No Windows settings are changed. Run with powershell.exe 5.1 or pwsh.
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$script:ScriptRoot = $repo
# Load trusted source functions into the same scope as the mocks. Windows
# PowerShell 5.1 otherwise resolves a script-local original ahead of global mocks.
$definitions = Get-Content -LiteralPath (Join-Path $repo 'scripts/Configuration.ps1') -Raw
Invoke-Expression ($definitions -replace '(?m)^function ', 'function global:')
$script:passed = 0
function Assert($Condition, [string]$Message) {
    if (-not $Condition) { throw "FAIL: $Message" }
    $script:passed++
}
function New-TestContext([switch]$DryRun) {
    $path = Join-Path ([IO.Path]::GetTempPath()) ('wela-results-test-' + [guid]::NewGuid().ToString('N'))
    if (-not $DryRun) { $script:cleanup.Add($path) }
    New-WelaConfigurationContext -Auto -DryRun:$DryRun -BackupPath $path
}
$script:cleanup = New-Object 'System.Collections.Generic.List[string]'
try {
    foreach ($path in @('WELA.ps1', 'scripts/Configuration.ps1')) {
        $parseErrors = $null; $tokens = $null
        $null = [Management.Automation.Language.Parser]::ParseFile((Join-Path $repo $path), [ref]$tokens, [ref]$parseErrors)
        Assert ($parseErrors.Count -eq 0) "Parser accepts $path"
    }

    # An actual child process exercises exit capture and stderr retention. The
    # child only emits text and exits; it never calls Windows configuration tools.
    $engine = (Get-Process -Id $PID).Path
    $caught = ''
    try { Invoke-WelaNative -FilePath $engine -Arguments @('-NoProfile', '-Command', "[Console]::Error.WriteLine('injected native diagnostic'); exit 7") }
    catch { $caught = $_.ToString() }
    Assert ($caught -match 'exit: 7' -and $caught -match 'injected native diagnostic') 'Native failure retains exit code and stderr'
    $ok = Invoke-WelaNative -FilePath $engine -Arguments @('-NoProfile', '-Command', "[Console]::Error.WriteLine('non-fatal diagnostic'); exit 0")
    Assert ($ok.ExitCode -eq 0 -and $ok.Diagnostic -match 'non-fatal diagnostic') 'Stderr alone is not a native failure'

    $script:state = 1; $script:writes = 0
    $read = { $script:state }; $test = { param($value) $value -eq 2 }
    $apply = { $script:writes++; $script:state = 2 }
    $c = New-TestContext
    Invoke-WelaConfigurationControl $c test Registry @{ Path = 'mock'; Name = 'value' } 2 $read $test $apply
    Assert ($c.Results[0].Status -eq 'Applied' -and $script:writes -eq 1) 'Changed state is read back before Applied'
    $journal = Get-Content -LiteralPath (Join-Path $c.BackupPath 'before.jsonl') | ConvertFrom-Json
    Assert ($journal.Before -eq 1 -and $journal.Desired -eq 2) 'Journal contains exact before and requested state'
    Invoke-WelaConfigurationControl $c repeated Registry @{} 2 $read $test $apply
    Assert ($c.Results[1].Status -eq 'AlreadyCompliant' -and $script:writes -eq 1) 'Rerun is idempotent'
    $r = Complete-WelaConfiguration $c
    Assert ($r.ExitCode -eq 0) 'Verified controls produce successful overall status'
    $script:state = 1
    $r = Complete-WelaConfiguration $c
    Assert ($r.ExitCode -eq 1 -and $r.Results[0].Status -eq 'Overridden') 'Final check detects observed drift without attributing its cause'

    $c = New-TestContext -DryRun
    $script:writes = 0
    Invoke-WelaConfigurationControl $c dry Registry @{} 2 $read $test $apply
    Assert ($c.Results[0].Status -eq 'Skipped' -and $script:writes -eq 0) 'Dry run never invokes mutation'
    Assert (-not (Test-Path -LiteralPath $c.BackupPath)) 'Dry run creates no backup or journal'

    $c = New-TestContext
    Invoke-WelaConfigurationControl $c false_success Registry @{} 2 $read $test { }
    Assert ($c.Results[0].Status -eq 'Failed') 'Successful write command with wrong read-back is Failed'
    Assert ((Complete-WelaConfiguration $c).ExitCode -eq 1) 'Read-back failure makes overall status nonzero'

    $c = New-TestContext
    $c.BackupPath = Join-Path $c.BackupPath 'missing-parent'
    $script:writes = 0
    Invoke-WelaConfigurationControl $c journal_failed Registry @{} 2 $read $test $apply
    Assert ($c.Results[0].Status -eq 'Failed' -and $script:writes -eq 0) 'Journal failure prevents mutation'

    # Registry provider failures and false-success writes use the same verified
    # control runner; no actual registry provider is touched in these tests.
    $script:registryValue = 0; $script:registryWrites = 0; $script:registryThrows = $true
    function global:Get-WelaRegistryState {
        param($Path, $Name)
        [pscustomobject]@{ KeyExists = $true; ValueExists = $true; Value = $script:registryValue; Type = 'DWord' }
    }
    function global:Test-Path {
        param($LiteralPath, $Path, $ErrorAction)
        if ($LiteralPath -like 'HKLM:*') { return $true }
        Microsoft.PowerShell.Management\Test-Path -LiteralPath $(if ($LiteralPath) { $LiteralPath } else { $Path })
    }
    function global:Set-ItemProperty {
        param($LiteralPath, $Name, $Value, $Type, $ErrorAction)
        $script:registryWrites++
        if ($script:registryThrows) { throw 'Injected registry access denied' }
        $script:registryValue = $Value
    }
    $c = New-TestContext
    Set-WelaRegistryControl $c 'HKLM:\mock' Value 1
    Assert ($c.Results[0].Status -eq 'Failed' -and $c.Results[0].Diagnostic -match 'access denied') 'Registry write errors produce failed results'
    $script:registryThrows = $false
    $c = New-TestContext
    Set-WelaRegistryControl $c 'HKLM:\mock' Value 1
    Assert ($c.Results[0].Status -eq 'Applied' -and $c.Results[0].After.Value -eq 1) 'Registry writes require verified value and type'
    $beforeWrites = $script:registryWrites
    Set-WelaRegistryControl $c 'HKLM:\mock' Value 1
    Assert ($c.Results[1].Status -eq 'AlreadyCompliant' -and $script:registryWrites -eq $beforeWrites) 'Registry reruns preserve compliant values'

    # Missing nested registry parents must be created individually, retaining
    # existing parent keys/values. Mock provider rejects children without parents.
    $script:mockKeys = @{'HKLM:' = $true; 'HKLM:\SOFTWARE' = $true}
    $script:createdKeys = New-Object 'System.Collections.Generic.List[string]'
    function global:Test-Path {
        param($LiteralPath, $Path, $ErrorAction)
        if ($LiteralPath -like 'HKLM:*') { return $script:mockKeys.ContainsKey($LiteralPath) }
        Microsoft.PowerShell.Management\Test-Path -LiteralPath $(if ($LiteralPath) { $LiteralPath } else { $Path })
    }
    function global:New-Item {
        param($Path, $ItemType, [switch]$Force, $ErrorAction)
        if ($Path -notlike 'HKLM:*') { return Microsoft.PowerShell.Management\New-Item @PSBoundParameters }
        if ($Force) { throw 'Test refuses Force on registry keys' }
        if ($script:mockKeys.ContainsKey($Path)) { throw 'Existing parent would be recreated' }
        $parent = $Path.Substring(0, $Path.LastIndexOf('\'))
        if (-not $script:mockKeys.ContainsKey($parent)) { throw "Missing registry parent: $parent" }
        $script:createdKeys.Add($Path); $script:mockKeys[$Path] = $true
    }
    New-WelaRegistryKey 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    Assert ($script:createdKeys.Count -eq 5 -and $script:mockKeys.ContainsKey('HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging')) 'Missing registry ancestors are created safely in order'
    New-WelaRegistryKey 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    Assert ($script:createdKeys.Count -eq 5) 'Existing registry parents are preserved on rerun'

    # Function stubs stand in for the Windows APIs from this point onward.
    $script:logSize = 1048576; $script:nativeFails = $true; $script:nativeWrites = 0
    function global:Get-WinEvent { param($ListLog, $ErrorAction) [pscustomobject]@{ MaximumSizeInBytes = $script:logSize; IsEnabled = $false } }
    function global:Invoke-WelaNative {
        param($FilePath, $Arguments)
        $script:nativeWrites++
        if ($script:nativeFails) { throw 'wevtutil.exe failed (exit: 5). Injected access denied' }
        $script:logSize = 134217728
        [pscustomobject]@{ ExitCode = 0; Output = @(); Diagnostic = 'mock success' }
    }
    $c = New-TestContext
    Set-WelaEventLogControl $c Security MaximumSizeInBytes 134217728
    $r = Complete-WelaConfiguration $c
    Assert ($r.ExitCode -eq 1 -and $r.Results[0].Diagnostic -match 'access denied') 'Injected wevtutil failure survives through the final report'
    $script:nativeFails = $false
    $c = New-TestContext
    Set-WelaEventLogControl $c Security MaximumSizeInBytes 134217728
    Assert ($c.Results[0].Status -eq 'Applied') 'Event log helper reads verified size'
    Set-WelaEventLogControl $c Security MaximumSizeInBytes 134217728
    Assert ($c.Results[1].Status -eq 'AlreadyCompliant') 'Event log helper avoids repeated writes'

    # Compile the interop declaration without invoking Windows APIs on this host.
    Initialize-WelaConfigurationAuditApi
    Assert ($null -ne ('Wela.ConfigurationAuditApi' -as [type])) 'Audit query interop compiles'
    function global:Get-WelaNativeAuditPolicy { param($Guid) return 3 }
    Assert ((Get-WelaAuditPolicyMask '0CCE922B-69AE-11D9-BED3-505054503030') -eq 3) 'Audit policy uses native numeric flags independent of locale'
    function global:Get-WelaNativeAuditPolicy { param($Guid) return 4 }
    Assert ((Get-WelaAuditPolicyMask '0CCE922B-69AE-11D9-BED3-505054503030') -eq 0) 'Native NONE flag normalizes to no success/failure audit'
    function global:Get-WelaNativeAuditPolicy { param($Guid) return 16 }
    $caught = ''
    try { Get-WelaAuditPolicyMask '0CCE922B-69AE-11D9-BED3-505054503030' } catch { $caught = $_.ToString() }
    Assert ($caught -ne '') 'Unexpected native flags cannot be marked compliant'

    # Extract ConfigureAuditSettings without running the WELA command dispatcher.
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'WELA.ps1'), [ref]$tokens, [ref]$errors)
    $configure = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'ConfigureAuditSettings' }, $false)
    Assert ($configure.Extent.Text -notmatch 'Configuration completed successfully|Start-Process|Out-Null') 'Configure has no unverified native execution or unconditional success'

    # Run the actual configure dispatcher in a child process with only the
    # configuration function replaced by a harmless failed-report fixture.
    $dispatch = $ast.Find({ param($node) $node -is [Management.Automation.Language.SwitchStatementAst] -and $node.Condition.Extent.Text -eq '$Cmd.ToLower()' }, $false)
    $clause = @($dispatch.Clauses | Where-Object { $_.Item1.Value -eq 'configure' })[0].Item2.Extent.Text
    $child = 'function ConfigureAuditSettings { [pscustomobject]@{ ExitCode = 1; Failed = 1; Results = @() } }; & ' + $clause
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($child))
    $childOutput = @(& $engine -NoProfile -EncodedCommand $encoded 2>&1)
    $childExit = $global:LASTEXITCODE
    # GitHub's PowerShell wrapper propagates LASTEXITCODE after the script. This
    # child was deliberately failed; assertions below decide the test outcome.
    $global:LASTEXITCODE = 0
    Assert ($childExit -eq 1) 'The actual configure dispatcher returns nonzero for a failed control report'

    # CA-specific wrapper: registry read succeeds, certutil succeeds, restart
    # fails. All APIs below are mocks, including Test-Path for the mock CA only.
    $realTestPath = (Get-Command Test-Path).Name
    function global:Test-Path {
        param($LiteralPath, $Path, $ErrorAction)
        if ($LiteralPath -like 'HKLM:*') { return $true }
        Microsoft.PowerShell.Management\Test-Path -LiteralPath $(if ($LiteralPath) { $LiteralPath } else { $Path })
    }
    function global:Get-ItemProperty { param($LiteralPath, $Name, $ErrorAction) [pscustomobject]@{ Active = 'MockCA' } }
    function global:Join-Path {
        param($Path, $ChildPath)
        if ($Path -like 'HKLM:*') { return "$Path\$ChildPath" }
        Microsoft.PowerShell.Management\Join-Path -Path $Path -ChildPath $ChildPath
    }
    $script:filter = 0; $script:restartCalls = 0; $script:filterType = 'DWord'
    function global:Get-WelaRegistryState { param($Path, $Name) [pscustomobject]@{ ValueExists = $true; Value = $script:filter; Type = $script:filterType; KeyExists = $true } }
    function global:Get-Service { param($Name, $ErrorAction) [pscustomobject]@{ Status = 'Running' } }
    function global:Restart-Service { param($Name, [switch]$Force, $ErrorAction) $script:restartCalls++; throw 'Injected CertSvc restart failure' }
    function global:Invoke-WelaNative { param($FilePath, $Arguments) $script:filter = 127; [pscustomobject]@{ ExitCode = 0; Diagnostic = 'mock certutil' } }
    $c = New-TestContext
    Set-WelaCertificateAuditControl $c
    $r = Complete-WelaConfiguration $c
    Assert ($r.ExitCode -eq 1 -and $r.Results[0].Diagnostic -match 'restart failure') 'CA restart failure cannot report success even when registry now equals 127'
    $script:filter = 0; $script:restartCalls = 0
    function global:Invoke-WelaNative { param($FilePath, $Arguments) throw 'certutil failed (exit: 5)' }
    $c = New-TestContext
    Set-WelaCertificateAuditControl $c
    Assert ($c.Results[0].Status -eq 'Failed' -and $script:restartCalls -eq 0) 'Failed certutil never restarts the CA'
    $c = New-TestContext -DryRun
    Set-WelaCertificateAuditControl $c
    Assert ($c.Results[0].Status -eq 'Skipped' -and $script:restartCalls -eq 0) 'CA dry run never writes or restarts'

    $script:filter = '127'; $script:filterType = 'String'
    $c = New-TestContext -DryRun
    Set-WelaCertificateAuditControl $c
    Assert ($c.Results[0].Status -eq 'Skipped') 'REG_SZ 127 is not accepted as a compliant CA DWORD AuditFilter'

    Write-Host "$script:passed configuration-result regression assertions passed. No Windows settings changed."
} finally {
    foreach ($path in $script:cleanup) {
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Recurse -Force
        }
    }
}
