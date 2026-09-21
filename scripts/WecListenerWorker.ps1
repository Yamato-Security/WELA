param([string]$RequestPath,[string]$RequestHash)
$env:PSModulePath=[IO.Path]::Combine([Environment]::SystemDirectory,'WindowsPowerShell\v1.0\Modules')
$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if($args.Count -or $PSVersionTable.PSVersion.Major -ne 5 -or -not [Environment]::Is64BitProcess){throw 'Only the fixed native Windows PowerShell 5.1 listener adapter is supported.'}
$script:ScriptRoot=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $script:ScriptRoot 'modules/AuditProfiles.psm1') -Force
Import-Module (Join-Path $script:ScriptRoot 'modules/WefSubscriptions.psm1') -Force
. (Join-Path $PSScriptRoot 'WefArrival.ps1')
. (Join-Path $PSScriptRoot 'WecUpdate.ps1')
. (Join-Path $PSScriptRoot 'ChannelRead.ps1')
. (Join-Path $PSScriptRoot 'WecListener.ps1')
$report=Invoke-WelaListenerWorkerRequest $RequestPath $RequestHash
$report|ConvertTo-Json -Depth 24 -Compress
if($report.Status -cne 'Created'){exit 1}
