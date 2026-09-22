# Value-only recovery for three built-in logging switches. No arbitrary registry replay.
function Get-WelaNamedRecoveryCatalog {
    foreach ($item in @(
        @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit','ProcessCreationIncludeCmdLine_Enabled'),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging','EnableScriptBlockLogging'),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging','EnableModuleLogging')
    )) {[pscustomobject]@{Id=('Registry/'+$item[0]+'/'+$item[1]);Path=$item[0];Name=$item[1]}}
}
function Get-WelaNamedRecoverySources {
    foreach ($relative in @('scripts/NamedRegistryRecovery.ps1','scripts/NamedRegistryRecoveryNative.cs','scripts/AuditRecovery.ps1','scripts/Configuration.ps1')) {
        [pscustomobject]@{Path=$relative;Sha256=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot ('../'+$relative)) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()}
    }
}
function Initialize-WelaNamedRecoveryNative {
    $path=Join-Path $PSScriptRoot 'NamedRegistryRecoveryNative.cs'
    $bytes=[IO.File]::ReadAllBytes($path);$hash=Get-WelaRecoveryHash $bytes
    if ('Wela.NamedRegistryRecovery.Key' -as [type]) {
        if ([Wela.NamedRegistryRecovery.Key]::SourceSha256 -cne $hash) {throw 'Loaded named-registry native source differs; start a fresh process.'}
        return
    }
    $source=(New-Object Text.UTF8Encoding($false,$true)).GetString($bytes).Replace('__WELA_SOURCE_SHA256__',$hash)
    Add-Type -TypeDefinition $source -ErrorAction Stop
}
function Assert-WelaNamedRecoveryValue {
    param($State)
    if ($State.KeyExists -isnot [bool] -or $State.ValueExists -isnot [bool]) {throw 'Logging registry state requires typed existence flags.'}
    if ($State.ValueExists) {
        if (-not $State.KeyExists -or $State.Type -cne 'DWord' -or ($State.Value -isnot [int] -and $State.Value -isnot [long]) -or $State.Value -notin @(0,1)) {throw 'Only prior DWORD 0/1 or value absence is supported.'}
    } elseif ($null -ne $State.Value -or $null -ne $State.Type) {throw 'Absent logging value has inconsistent state.'}
}
function Get-WelaNamedRecoveryGuard {
    param($Observation)
    [pscustomobject][ordered]@{ObjectName=$Observation.ObjectName;OtherValues=$Observation.OtherValues;Children=$Observation.Children;Security=$Observation.Security}
}
function Get-WelaNamedRecoveryState {
    param($Observation)
    [pscustomobject]@{KeyExists=$true;ValueExists=[bool]$Observation.Exists;Value=$(if ($Observation.Exists) {[int]$Observation.Value} else {$null});Type=$(if ($Observation.Exists) {'DWord'} else {$null})}
}
function Open-WelaNamedRecoveryKey {
    param($Target,[bool]$Write=$false)
    $known=@(Get-WelaNamedRecoveryCatalog | Where-Object {$_.Path -ceq $Target.Path -and $_.Name -ceq $Target.Name})
    if ($known.Count -ne 1) {throw 'Unknown logging recovery target.'}
    Initialize-WelaNamedRecoveryNative
    [Wela.NamedRegistryRecovery.Key]::new($Target.Path,$Write)
}
function Get-WelaNamedRecoveryObservation {
    param($Target)
    $key=Open-WelaNamedRecoveryKey $Target
    try {
        $observation=$key.Read($Target.Name)
        if ($observation.ObjectName -ine ('\REGISTRY\MACHINE\'+$Target.Path.Substring(6))) {throw 'Native registry name does not match the selected path.'}
        $observation
    } finally {$key.Dispose()}
}
function Assert-WelaNamedRecoveryGuard {
    param($Control,$Observation)
    if ((Get-WelaRecoveryKey (Get-WelaNamedRecoveryGuard $Observation)) -cne (Get-WelaRecoveryKey $Control.RegistryGuard)) {throw 'Logging registry path, other values, children or security changed since planning.'}
}
function Set-WelaNamedRecoveryValue {
    param($Control)
    $key=Open-WelaNamedRecoveryKey $Control.Target $true
    try {
        $before=$key.Read($Control.Target.Name)
        Assert-WelaNamedRecoveryGuard $Control $before
        if ((Get-WelaRecoveryKey (Get-WelaNamedRecoveryState $before)) -cne (Get-WelaRecoveryKey $Control.Expected)) {throw 'Logging value changed before recovery.'}
        $value=if ($Control.RecoverTo.ValueExists) {[int]$Control.RecoverTo.Value} else {0}
        $after=$key.Restore($Control.Target.Name,$before,$Control.RecoverTo.ValueExists,$value)
        Assert-WelaNamedRecoveryGuard $Control $after
        # Reopen the selected path after the handle-based write to detect visible path drift.
        $fresh=Get-WelaNamedRecoveryObservation $Control.Target
        Assert-WelaNamedRecoveryGuard $Control $fresh
        if ((Get-WelaRecoveryKey (Get-WelaNamedRecoveryState $fresh)) -cne (Get-WelaRecoveryKey $Control.RecoverTo)) {throw 'Reopened logging value differs after recovery.'}
    } finally {$key.Dispose()}
}
