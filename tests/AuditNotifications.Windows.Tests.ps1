$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'scripts/Configuration.ps1')
. (Join-Path $root 'scripts/NativeChannelConfiguration.ps1')
. (Join-Path $root 'scripts/AuditNotifications.ps1')
Import-Module (Join-Path $root 'modules/NativeProviders.psm1')
$before=@(Get-WelaNotificationDefinitions | ForEach-Object { Get-WelaRegistryState -Path $_.Path -Name $_.Name }) | ConvertTo-Json -Depth 8
$report=Invoke-WelaNotificationCommand -Action Audit
if ($report.Current.Count -ne 2) { throw 'Audit omitted a control.' }
$hostState=Get-WelaNotificationHost
if ($hostState.Status -ne 'Supported') { throw "Unexpected native host state: $($hostState.Diagnostic)" }
$warning=@($report.Current | Where-Object {$_.Definition.Id -eq 'SecurityWarning'})[0]
if ($warning.Before.Channel.Name -ne 'Security' -or $warning.Before.Status -ne 'Supported') { throw 'Native Security policy/channel observation failed.' }
$after=@(Get-WelaNotificationDefinitions | ForEach-Object { Get-WelaRegistryState -Path $_.Path -Name $_.Name }) | ConvertTo-Json -Depth 8
if ($before -cne $after) { throw 'Read-only audit changed policy.' }
$report | ConvertTo-Json -Depth 18 | Write-Host
Write-Host 'PASS: native read-only policy/channel observations; event generation not tested.'
$global:LASTEXITCODE=0
