$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Windows required.' }
. (Join-Path $PSScriptRoot '../scripts/TargetedSaclPlanning.ps1')
$inventory = Get-WelaSaclUserInventory
if ($null -eq $inventory.PSObject.Properties['Complete']) { throw 'User inventory did not report completeness.' }
# Read a real, existing local object. Lack of SACL read privilege stays explicit.
$observation = Get-WelaSaclTargetObservation -Path "$env:SystemRoot\System32\cmd.exe" -Kind FileSystem
if ($observation.PathState -ne 'Exists') { throw ($observation | ConvertTo-Json) }
if ($observation.SaclReadState -notin @('Readable', 'Inaccessible')) { throw 'Unexpected native SACL read state.' }
$missing = Get-WelaSaclTargetObservation -Path (Join-Path $env:TEMP ([guid]::NewGuid().ToString('N'))) -Kind FileSystem
if ($missing.PathState -ne 'Missing') { throw 'Missing native target misclassified.' }
$registry = Get-WelaSaclTargetObservation -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion' -Kind Registry
if ($registry.PathState -ne 'Exists') { throw ($registry | ConvertTo-Json) }
Write-Host 'PASS: read-only ProfileList/HKU and native file/registry observations. No policy, ACL or hive changes.'
