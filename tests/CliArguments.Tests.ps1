# Public process-boundary regression: no mocked dispatcher or Windows writers.
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$engine = (Get-Process -Id $PID).Path
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
            Invoke-Case ($command + @('-BackupPath',"$root/journal",'-ResultsPath',"$root/result.json",$unknown)) 1 'Unsupported trailing arguments'
            Assert (-not (Test-Path "$root/journal") -and -not (Test-Path "$root/result.json")) 'Rejected arguments must not create journals/results'
        }
    }
    # Unknown argument values are deliberately omitted from WELA's diagnostic.
    Invoke-Case @('configure','-Auto','-UnrecognizedOption','opaque-value') 1 'Unsupported trailing arguments'
    Invoke-Case @('configure','-Help','-WhatIf:$false') 1 'Unsupported trailing arguments'
    Invoke-Case @('-WhatIf','configure','-Auto') 1 'Unsupported trailing arguments'
    # Preserve documented named/positional binding, help, abbreviations and DryRun.
    Invoke-Case @('configure','-Help','-Auto','-DryRun') 0 'Read live state'
    Invoke-Case @('-Cmd','configure','-Help') 0 'Usage:'
    Invoke-Case @('configure','std','-Help') 0 'Usage:'
    Invoke-Case @('configure','-Hel') 0 'Usage:'
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
