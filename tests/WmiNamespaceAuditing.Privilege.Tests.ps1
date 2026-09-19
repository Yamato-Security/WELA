# Compile the production privilege lifecycle with in-memory native API substitutes.
# No process token or live WMI namespace is modified by this test.
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$source = Get-Content -LiteralPath (Join-Path $repo 'scripts/WmiNamespaceAuditing.ps1') -Raw
. (Join-Path $repo 'scripts/WmiNamespaceAuditing.ps1')
$script:assertions = 0
function Assert($Condition, [string]$Message) { if (-not $Condition) { throw "FAIL: $Message" }; $script:assertions++ }
$match = [regex]::Match($source, "(?s)Add-Type -TypeDefinition @'\r?\n(.*?)\r?\n'@ -ErrorAction Stop")
Assert $match.Success 'Production privilege helper located'
$csharp = $match.Groups[1].Value.Replace('namespace Wela {', 'namespace WelaPrivilegeFixture {')
# Replace only external API declarations/error reads, retaining constructor and
# Dispose control flow from the shipped helper rather than mirroring that logic.
$csharp = [regex]::Replace($csharp, '(?m)^  \[DllImport[^\r\n]+\r?\n', '')
$csharp = $csharp.Replace('Marshal.GetLastWin32Error()', 'TestError')
$native = @'
  public static int TestError, EnableError, RestoreError, AdjustCalls, CloseCalls;
  public static bool RestoreSuccess = true;
  public static void Reset() { TestError=EnableError=RestoreError=AdjustCalls=CloseCalls=0; RestoreSuccess=true; }
  static IntPtr GetCurrentProcess() { return (IntPtr)1; }
  static bool CloseHandle(IntPtr handle) { CloseCalls++; return true; }
  static bool OpenProcessToken(IntPtr process, uint access, out IntPtr token) { token=(IntPtr)2; return true; }
  static bool LookupPrivilegeValue(string system, string name, out Luid luid) { luid=new Luid(); return true; }
  static bool AdjustTokenPrivileges(IntPtr token, bool disable, ref TokenPrivileges current, uint size, out TokenPrivileges previous, out uint required) {
   previous=current; previous.Attributes=0; required=16;
   AdjustCalls++; TestError=AdjustCalls==1 ? EnableError : RestoreError;
   return AdjustCalls==1 || RestoreSuccess;
  }
'@
$csharp = $csharp.Replace('  IntPtr token;', $native + "`n  IntPtr token;")
Assert ($csharp -notmatch '\[DllImport') 'All token API imports are replaced before compilation'
Add-Type -TypeDefinition $csharp -ErrorAction Stop
$type = [WelaPrivilegeFixture.WmiSecurityPrivilege]
$type::Reset()
$instance = [WelaPrivilegeFixture.WmiSecurityPrivilege]::new()
$instance.Dispose(); $instance.Dispose()
Assert ($type::AdjustCalls -eq 2 -and $type::CloseCalls -eq 1) 'Normal restoration executes once and closes the token once'
foreach ($restoreError in @(1300, 5)) {
    $type::Reset(); $type::RestoreError = $restoreError
    $instance = [WelaPrivilegeFixture.WmiSecurityPrivilege]::new()
    $failed = $false
    try { $instance.Dispose() } catch { $failed = $_.Exception.InnerException.NativeErrorCode -eq $restoreError }
    Assert $failed 'A true AdjustTokenPrivileges return with nonzero last error is a restoration failure'
    Assert ($type::CloseCalls -eq 1) 'Failed privilege restoration still closes the token handle'
}
$type::Reset(); $type::RestoreError = 5; $type::RestoreSuccess = $false
$instance = [WelaPrivilegeFixture.WmiSecurityPrivilege]::new()
$failed = $false; try { $instance.Dispose() } catch { $failed = $true }
Assert ($failed -and $type::CloseCalls -eq 1) 'False API restoration result is reported and handle is closed'
$type::Reset(); $type::EnableError = 1300
$failed = $false; try { [WelaPrivilegeFixture.WmiSecurityPrivilege]::new() } catch { $failed = $true }
Assert ($failed -and $type::AdjustCalls -eq 1 -and $type::CloseCalls -eq 1) 'Unavailable SeSecurityPrivilege refuses the operation and closes its handle'

# Exercise the production PowerShell cleanup paths with a throwing connection.
function Initialize-WelaWmiInterop { }
$script:disposed = 0
$script:privilegeFixture = [pscustomobject]@{}
$script:privilegeFixture | Add-Member ScriptMethod Dispose { $script:disposed++ }
function New-Object {
    param([string]$TypeName, [object[]]$ArgumentList)
    if ($TypeName -eq 'Wela.WmiSecurityPrivilege') { return $script:privilegeFixture }
    throw "Unexpected construction in failure fixture: $TypeName"
}
$script:connectionFixture = [pscustomobject]@{}
$script:connectionFixture | Add-Member ScriptMethod Dispose { throw 'fixture COM cleanup failure' }
function New-WelaWmiConnection { param($Namespace) return $script:connectionFixture }
function Get-WelaWmiNativeDescriptor { param($Connection) throw 'fixture descriptor read failure' }
foreach ($operation in @('Get', 'Set')) {
    $before = $script:disposed; $failed = $false
    try {
        if ($operation -eq 'Get') { Get-WelaWmiNamespaceSnapshot 'root\cimv2' }
        else { Set-WelaWmiNamespaceDescriptor 'root\cimv2' '{}' @() }
    } catch { $failed = $true }
    Assert ($failed -and $script:disposed -eq $before + 1) "$operation restores privilege even when connection cleanup throws"
}
Write-Host "PASS: $script:assertions WMI privilege/cleanup assertions with in-memory APIs only."
