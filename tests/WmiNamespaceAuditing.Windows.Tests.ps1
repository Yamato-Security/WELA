# Actual reads and in-memory typed provider responses only. Never sends a native SetSecurityDescriptor.
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { Write-Host 'SKIP: Windows only'; return }
$repo = Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/WmiNamespaceAuditing.ps1')
$script:assertions = 0
function Assert($Condition, [string]$Message) { if (-not $Condition) { throw "FAIL: $Message" }; $script:assertions++ }
$before = Get-WelaWmiNamespaceSnapshot 'root\cimv2'
Assert ($before.DescriptorJson -and $before.DescriptorMof -and $before.SaclReadPrivilege -eq 'SeSecurityPrivilege enabled') 'Actual privileged native descriptor read and full export'
$inventory = @(Get-WelaWmiNamespaceInventory)
Assert ($inventory.Count -eq 5 -and @($inventory | Where-Object { $_.Namespace -eq 'root\cimv2' -and $_.State -eq 'Present' }).Count -eq 1) 'Supported namespace inventory reads actual local namespaces'
$plan = @(Get-WelaWmiAuditPlan -Namespace 'root\cimv2')
Assert ($plan[0].Status -in @('AlreadyCompliant','ChangeRequired')) 'Actual CIMV2 plan reads successfully'
$path = Join-Path ([IO.Path]::GetTempPath()) ('wela-wmi-readonly-' + [guid]::NewGuid().ToString('N'))
$context = New-WelaConfigurationContext -Auto -DryRun -BackupPath $path
Set-WelaWmiAuditControls -Context $context -Plan $plan
Assert (-not (Test-Path $path) -and $context.Results[0].Status -in @('AlreadyCompliant','Skipped')) 'Real dry-run neither writes SACL nor creates journal'
$after = Get-WelaWmiNamespaceSnapshot 'root\cimv2'
Assert ($before.DescriptorJson -ceq $after.DescriptorJson) 'Full descriptor unchanged by read-only planning/dry-run'
# Read actual native objects once; from here the native connection factory is
# replaced in the same script scope before invoking ANY setter code.
Initialize-WelaWmiInterop
$privilege = New-Object Wela.WmiSecurityPrivilege
$connection = $null
try {
    $connection = New-WelaWmiConnection 'root\cimv2'
    $script:fixtureDescriptor = (Get-WelaWmiNativeDescriptor $connection).Clone()
    $script:fixtureParameters = $connection.GetMethodParameters('SetSecurityDescriptor')
} finally { if ($connection) { $connection.Dispose() }; $privilege.Dispose() }
# An empty in-memory SACL forces all requested additions without changing Windows.
$script:fixtureDescriptor.SACL = $null
$expected = ConvertTo-WelaWmiJson (ConvertTo-WelaWmiData $script:fixtureDescriptor)
$script:setCalls = 0; $script:captured = $null; $script:returnCode = [uint32]0
$script:fake = [pscustomobject]@{}
$script:fake | Add-Member ScriptMethod InvokeMethod {
    param($Name, $Parameters, $Options)
    if ($Name -eq 'GetSecurityDescriptor') { return [pscustomobject]@{ ReturnValue = [uint32]0; Descriptor = $script:fixtureDescriptor } }
    if ($Name -ne 'SetSecurityDescriptor') { throw "Unexpected method: $Name" }
    $script:setCalls++; $script:captured = $Parameters.Descriptor.Clone()
    return [pscustomobject]@{ ReturnValue = $script:returnCode }
}
$script:fake | Add-Member ScriptMethod GetMethodParameters { param($Name) if ($Name -ne 'SetSecurityDescriptor') { throw 'Unexpected method parameters' }; return $script:fixtureParameters.Clone() }
$script:fake | Add-Member ScriptMethod Dispose { }
function New-WelaWmiConnection { param($Namespace) if ($Namespace -ne 'root\cimv2') { throw 'Unexpected fake target' }; return $script:fake }
$definitions = @(Get-WelaWmiAuditDefinitions -Namespace 'root\cimv2')
Set-WelaWmiNamespaceDescriptor -Namespace 'root\cimv2' -ExpectedJson $expected -Definitions $definitions
Assert ($script:setCalls -eq 1 -and $script:captured -is [System.Management.ManagementBaseObject]) 'Production writer builds typed descriptor against fake provider only'
$original = $expected | ConvertFrom-Json
$captured = ConvertTo-WelaWmiData $script:captured
Assert ($null -eq $captured.DACL -and $null -eq $captured.Owner -and $null -eq $captured.Group) 'Native request omits access-permission fields instead of requesting that they be rewritten'
Assert (([uint32]$captured.ControlFlags -band 4) -eq 0 -and ([uint32]$captured.ControlFlags -band 16) -eq 16) 'Native request uses only SACL-present mutation semantics, with DACL-present cleared'
Assert ((ConvertTo-WelaWmiJson (ConvertTo-WelaWmiData $script:fixtureDescriptor)) -ceq $expected) 'Building the SACL-only request leaves the complete original descriptor unchanged'
# Simulate the documented provider contract in memory: absent access fields and
# SE_DACL_PRESENT preserve the current access permissions.
$effective = $expected | ConvertFrom-Json
$effective.SACL = $captured.SACL
$effective.ControlFlags = [uint32]$effective.ControlFlags -bor 16
Assert (Test-WelaWmiDescriptorPreserved $original $effective) 'SACL-only provider semantics retain every original non-SACL field'
Assert (@(Get-WelaWmiMissingAces $captured $definitions).Count -eq 0 -and @($captured.SACL).Count -eq 4) 'Actual Win32_ACE/Trustee objects carry all four exact masks and binary SIDs'
$script:returnCode = [uint32]9
$failed = $false
try { Set-WelaWmiNamespaceDescriptor -Namespace 'root\cimv2' -ExpectedJson $expected -Definitions $definitions } catch { $failed = $_.Exception.Message -match 'ReturnValue=9' }
Assert $failed 'Production SetSecurityDescriptor wrapper rejects native nonzero return code'
$prior = $script:setCalls; $failed = $false
try { Set-WelaWmiNamespaceDescriptor -Namespace 'root\cimv2' -ExpectedJson '{}' -Definitions $definitions } catch { $failed = $_.Exception.Message -match 'changed after' }
Assert ($failed -and $script:setCalls -eq $prior) 'Production writer detects changed snapshot before fake setter'
Write-Host "PASS: $script:assertions Windows namespace read-only / in-memory native adapter assertions. No live SACL changes or event-generation claims."
