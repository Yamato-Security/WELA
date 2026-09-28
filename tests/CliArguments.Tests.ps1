# Public process-boundary regression: no mocked dispatcher or Windows writers.
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$engine = (Get-Process -Id $PID).Path
. "$repo/scripts/CommandParameterValidation.ps1"
$count = 0
$root = Join-Path ([IO.Path]::GetTempPath()) ('wela-cli-arguments-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $root
function Assert($Value, $Message) { if (-not $Value) { throw $Message }; $script:count++ }
function Invoke-Case([string[]]$Arguments, [int]$Expected, [string]$Pattern) {
    $prior = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & $engine -NoLogo -NoProfile -NonInteractive -File "$repo/WELA.ps1" @Arguments 2>&1 | Out-String
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $prior }
    Assert ($code -eq $Expected -and $output -match $Pattern) "Unexpected public CLI exit/output [$code]: $output"
}
$isWindowsHost = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
function Read-NativeState {
    $logs = @('Security','System','Application','ForwardedEvents','Microsoft-Windows-CAPI2/Operational')
    $state = [ordered]@{ Audit = Get-WelaEffectiveAuditPolicy; Channels = @() }
    foreach ($name in $logs) { $state.Channels += Get-WelaNativeChannel $name }
    return ($state | ConvertTo-Json -Depth 12 -Compress)
}
try {
    if ($isWindowsHost) {
        Import-Module "$repo/modules/AuditProfiles.psm1" -Force
        Import-Module "$repo/modules/NativeProviders.psm1" -Force
        $before = Read-NativeState
    }

    # Keep the validation table synchronized with both the public dispatcher and
    # the script-level parameter block. Predicate switch clauses are expanded so
    # wef-source and wec-collector are checked independently.
    $tokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile("$repo/WELA.ps1", [ref]$tokens, [ref]$parseErrors)
    Assert ($parseErrors.Count -eq 0) "WELA.ps1 must parse before its command contract is inspected: $($parseErrors -join '; ')"
    $dispatch = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.SwitchStatementAst] -and $node.Condition.Extent.Text -eq '$Cmd.ToLower()'
    }, $true))[0]
    Assert ($null -ne $dispatch) 'The public command dispatcher was not found'
    $commandsFromDispatcher = @(
        foreach ($clause in $dispatch.Clauses) {
            if ($clause.Item1 -is [Management.Automation.Language.StringConstantExpressionAst]) {
                $clause.Item1.Value
            } else {
                $clause.Item1.FindAll({
                    param($node)
                    $node -is [Management.Automation.Language.StringConstantExpressionAst]
                }, $true) | ForEach-Object Value
            }
        }
    ) | Sort-Object -Unique
    $scriptParameters = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
    $parameterMap = Get-WelaCommandParameterMap
    $mappedCommands = @($parameterMap.Keys | Sort-Object)
    $commandDifference = @(Compare-Object $commandsFromDispatcher $mappedCommands)
    Assert ($commandDifference.Count -eq 0) "Every dispatched command must have exactly one parameter contract: $($commandDifference | Out-String)"
    $mappedParameters = @($parameterMap.Values | ForEach-Object { $_ } | Sort-Object -Unique)
    $orphanedParameters = @($scriptParameters | Where-Object { $mappedParameters -notcontains $_ })
    Assert ($orphanedParameters.Count -eq 0) "Every declared parameter must belong to a command contract: $($orphanedParameters -join ', ')"

    foreach ($command in $mappedCommands) {
        $allowed = @($parameterMap[$command])
        Assert (@($allowed | Group-Object | Where-Object Count -gt 1).Count -eq 0) "$command has duplicate allowed parameters"
        Assert ($allowed -contains 'Cmd' -and $allowed -contains 'Help') "$command must retain named/positional command binding and Help"
        foreach ($parameter in $allowed) {
            Assert ($scriptParameters -contains $parameter) "$command names undeclared parameter $parameter"
        }

        $allowedBound = @{ Cmd = $command }
        foreach ($parameter in $allowed | Where-Object { $_ -ne 'Cmd' }) { $allowedBound[$parameter] = $true }
        Assert-WelaCommandParameters -Command $command -BoundParameters $allowedBound -ParameterMap $parameterMap
        Assert $true "$command's documented parameters must pass the central validator"

        # Exhaustively exercise the validator with every globally recognized but
        # command-irrelevant parameter. Values are deliberately not inspected.
        foreach ($parameter in $scriptParameters | Where-Object { $allowed -notcontains $_ }) {
            $irrelevantBound = @{ Cmd = $command; $parameter = $true }
            $rejected = $false
            try {
                Assert-WelaCommandParameters -Command $command -BoundParameters $irrelevantBound -ParameterMap $parameterMap
            } catch {
                $rejected = $_.Exception.Message -match [regex]::Escape("-$parameter")
            }
            Assert $rejected "$command must reject recognized but irrelevant -$parameter"
        }
    }

    # One real process-boundary case per command proves that the central check is
    # wired before dispatch, not merely correct when called directly.
    foreach ($command in $mappedCommands) {
        # OutType belongs only to audit-settings and has no legacy pre-guard;
        # use one similarly central-only option for that single exception.
        $unsupported = if ($command -eq 'audit-settings') { 'OutgoingNtlmMode' } else { 'OutType' }
        $value = if ($command -eq 'audit-settings') { 'Audit' } else { 'std' }
        Invoke-Case @($command, "-$unsupported", $value) 1 '(?i)(does not support parameter|accepts only)'
    }

    # Public reproductions from issue #491, including a result path that must not
    # be created when validation stops the command.
    $issueResult = Join-Path $root 'profiles-result.json'
    $boundCases = @(
        @('profiles', '-ResultsPath', $issueResult),
        @('profiles', '-Auto'),
        @('profiles', '-OutgoingNtlmMode', 'Deny'),
        @('profiles', '-Baseline', 'ASD'),
        @('profiles', '-Debug'),
        @('eventlog-profiles', '-Auto'),
        @('version', '-Auto'),
        @('PrOfIlEs', '-Auto')
    )
    foreach ($case in $boundCases) {
        Invoke-Case $case 1 'does not support parameter'
    }
    Assert (-not (Test-Path -LiteralPath $issueResult)) 'Rejected -ResultsPath must not create a file'

    # These previously reached legacy writers, including the profile fast path.
    $commands = @(
        @('configure','-Auto'),
        @('configure','-Profile','wela-2.2.0','-Auto'),
        @('configure-eventlogs','-LogProfile','asd-collector-archive-2021-10','-ApplyLogMode','-Auto'),
        @('configure-sacl','-Auto'),
        @('channel-settings','-ChannelAction','Configure','-GrantEventLogReaders','-Auto'),
        @('powershell-transcription','-TranscriptionAction','Configure','-Auto'),
        @('firewall-logging','-FirewallAction','Configure','-Auto'),
        @('smb-auditing','-SmbAction','Configure','-Auto'),
        @('audit-integrity','-IntegrityAction','Configure','-Auto'),
        @('provider-packs','-ProviderAction','Configure','-Auto'),
        @('wec-collector','-WefAction','Configure','-Auto'),
        @('audit-settings','-Help')
    )
    foreach ($command in $commands) {
        foreach ($unknown in @('-WhatIf','-DryRnu')) {
            Invoke-Case ($command + @($unknown)) 1 'Unsupported trailing arguments'
        }
    }
    # Unknown argument values are deliberately omitted from WELA's diagnostic.
    Invoke-Case @('configure','-Auto','-UnrecognizedOption','opaque-value') 1 'Unsupported trailing arguments'
    Invoke-Case @('configure','-Help','-WhatIf:$false') 1 'Unsupported trailing arguments'
    Invoke-Case @('-WhatIf','configure','-Auto') 1 'Unsupported trailing arguments'
    # Preserve documented named/positional binding, help, abbreviations and DryRun.
    Invoke-Case @('configure','-Help','-Auto','-DryRun') 0 'Read live state'
    Invoke-Case @('-Cmd','configure','-Help') 0 'Usage:'
    Invoke-Case @('audit-settings','std','-Help') 0 'Usage:'
    Invoke-Case @('configure','-Hel') 0 'Usage:'
    Invoke-Case @('audit-filesize','-Baseline','YamatoSecurity','-Help') 0 'Usage:'
    Invoke-Case @('wef-source','-WefAction','Plan','-WefConfigPath','placeholder.json','-Help') 0 'wef-source|wec-collector'
    Invoke-Case @('profiles') 0 'wela-2.2.0'
    Invoke-Case @('failed-logon-probe','-FailedLogonAction','Run','-WhatIf') 1 'only dedicated'
    if ($isWindowsHost) {
        Assert ((Read-NativeState) -ceq $before) 'Actual audit masks and native channel settings must remain unchanged'
        $evidence = [ordered]@{ Status='Passed'; Engine=$PSVersionTable.PSVersion.ToString(); OS=[Environment]::OSVersion.Version.ToString(); StateUnchanged=$true; Before=($before|ConvertFrom-Json); After=((Read-NativeState)|ConvertFrom-Json) }
        if ($env:RUNNER_TEMP) { $evidence | ConvertTo-Json -Depth 16 | Set-Content (Join-Path $env:RUNNER_TEMP 'wela-cli-arguments.json') -Encoding UTF8 }
    }
    Write-Host "PASS: $count public CLI argument assertions."
} finally { Remove-Item -LiteralPath $root -Recurse -Force }
$global:LASTEXITCODE = 0
