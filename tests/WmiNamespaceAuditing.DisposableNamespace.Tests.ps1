# Actual SACL writes, confined to fresh temporary namespaces on a disposable VM.
# Existing namespaces are read only as the parent/factory; never passed to a setter.
param([switch]$AllowDisposableNamespaceWrite, [string]$EvidencePath)
$ErrorActionPreference = 'Stop'
if (-not $AllowDisposableNamespaceWrite) { throw 'This integration test requires -AllowDisposableNamespaceWrite on a disposable Windows VM.' }
if ($env:OS -ne 'Windows_NT') { throw 'Disposable-namespace integration requires Windows.' }
$repo = Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/WmiNamespaceAuditing.ps1')
Initialize-WelaWmiInterop
$script:assertions = 0
function Assert($Condition, [string]$Message) { if (-not $Condition) { throw "FAIL: $Message" }; $script:assertions++ }
$evidence = [pscustomobject]@{
    SchemaVersion = 1; Computer = $env:COMPUTERNAME; OperatingSystem = [Environment]::OSVersion.VersionString
    PowerShell = $PSVersionTable.PSVersion.ToString(); StartedUtc = [DateTime]::UtcNow.ToString('o')
    Scope = 'Real SACL write/readback on uniquely created root child namespaces only'
    EventGeneration = 'Not tested'; Forwarding = 'Not tested'; Cases = @(); Complete = $false
}
$backup = Join-Path ([IO.Path]::GetTempPath()) ('wela-wmi-integration-' + [guid]::NewGuid().ToString('N'))
try {
    foreach ($flags in @(64, 66)) {
        $name = 'WelaSaclTest_' + [guid]::NewGuid().ToString('N')
        $namespace = 'root\' + $name
        Assert ($namespace -match '^root\\WelaSaclTest_[0-9a-f]{32}$') 'Only the generated test namespace can receive writes'
        $created = $false; $factory = $null; $instance = $null
        $case = [pscustomobject]@{ Namespace=$namespace; AceFlags=$flags; Before=$null; After=$null; Result=$null; RepeatResult=$null; BeforeControlFlags=$null; ExpectedControlFlags=$null; AfterControlFlags=$null; Removed=$false }
        $evidence.Cases += $case
        try {
            # CreateOnly is essential: never adopt or delete an existing namespace.
            $factory = New-Object System.Management.ManagementClass -ArgumentList '\\.\root:__Namespace'
            $instance = $factory.CreateInstance(); $instance.Name = $name
            $options = New-Object System.Management.PutOptions
            $options.Type = [System.Management.PutType]::CreateOnly
            $createdPath = $instance.Put($options)
            $created = $true
            Assert ($createdPath.RelativePath -eq ('__NAMESPACE.Name="' + $name + '"')) 'Created namespace identity matches the generated name'
            $before = Get-WelaWmiNamespaceSnapshot $namespace
            $case.Before = $before
            $beforeData = $before.DescriptorJson | ConvertFrom-Json
            $case.BeforeControlFlags = [uint32]$beforeData.ControlFlags
            $case.ExpectedControlFlags = [uint32]$beforeData.ControlFlags -bor 16
            Assert (@($beforeData.SACL | Where-Object { $null -ne $_ }).Count -eq 0) 'Fixture exercises first SACL creation on a namespace with no existing audit ACEs'
            # Reuse the real ASD root-default mask/SID, with the test target and
            # explicit inheritance mode. Production profile scope is unchanged.
            $definitions = @(Get-WelaWmiAuditDefinitions -Namespace 'root\default' -IncludeChildren)
            $definitions[0].Namespace = $namespace; $definitions[0].AceFlags = [uint32]$flags
            $entry = [pscustomobject]@{ Namespace=$namespace; Definitions=$definitions }
            if($flags -eq 66){$entry|Add-Member NoteProperty Descendants (Get-WelaWmiStableDescendants $namespace)}
            $context = New-WelaConfigurationContext -Auto -BackupPath (Join-Path $backup ('first-' + $flags))
            Set-WelaWmiAuditControls -Context $context -Plan @($entry)
            $case.Result = Complete-WelaConfiguration -Context $context -Scope 'wmi-namespace-sacl-only'
            $after = Get-WelaWmiNamespaceSnapshot $namespace
            $case.After = $after
            $afterData = $after.DescriptorJson | ConvertFrom-Json
            $case.AfterControlFlags = [uint32]$afterData.ControlFlags
            Write-Host "Native flags: mode=$flags before=$($case.BeforeControlFlags) expected=$($case.ExpectedControlFlags) after=$($case.AfterControlFlags)"
            Assert ($case.Result.ExitCode -eq 0 -and $case.Result.Results[0].Status -eq 'Applied') 'Actual production runner accepts the provider readback after first SACL creation'
            Assert ($case.AfterControlFlags -eq $case.ExpectedControlFlags) 'Provider control flags match the exact preservation contract for this tested host/mode'
            Assert (Test-WelaWmiDescriptorPreserved $beforeData $afterData) 'Original access fields and existing ACEs survive the real SACL-only write'
            Assert (@(Get-WelaWmiMissingAces $afterData $definitions).Count -eq 0) 'Native provider stores the requested SID/mask/outcome/inheritance'
            $repeat = New-WelaConfigurationContext -Auto -BackupPath (Join-Path $backup ('repeat-' + $flags))
            if($flags -eq 66){$entry.Descendants=Get-WelaWmiStableDescendants $namespace}
            Set-WelaWmiAuditControls -Context $repeat -Plan @($entry)
            $case.RepeatResult = Complete-WelaConfiguration -Context $repeat -Scope 'wmi-namespace-sacl-only'
            Assert ($case.RepeatResult.ExitCode -eq 0 -and $case.RepeatResult.Results[0].Status -eq 'AlreadyCompliant') 'Repeated real configuration is idempotent'
            Assert ((Get-WelaWmiNamespaceSnapshot $namespace).DescriptorJson -ceq $after.DescriptorJson) 'Repeat leaves the full descriptor unchanged'
        } finally {
            try {
                if ($created) {
                    # The only deletion target is the instance this run created.
                    $instance.Delete()
                    $remaining = @(Get-CimInstance -Namespace root -ClassName __Namespace -Filter ("Name='$name'") -ErrorAction Stop)
                    Assert ($remaining.Count -eq 0) 'Owned temporary namespace was removed'
                    $case.Removed = $true
                }
            } finally {
                if ($instance) { $instance.Dispose() }
                if ($factory) { $factory.Dispose() }
            }
        }
    }
    $evidence.Complete = $true
    Write-Host "PASS: $script:assertions disposable-namespace native SACL assertions. Event generation and forwarding were not tested."
} finally {
    if ($EvidencePath) { $evidence | ConvertTo-Json -Depth 25 | Set-Content -LiteralPath $EvidencePath -Encoding UTF8 -ErrorAction Stop }
    if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Recurse -Force -ErrorAction Stop }
}
