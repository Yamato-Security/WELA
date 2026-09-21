# Opt-in local namespace SACLs. No namespace DACL, audit policy, or remote-access changes.
function Get-WelaWmiAuditDefinitions {
    param([string[]]$Namespace, [switch]$IncludeChildren)
    $source = 'https://github.com/AustralianCyberSecurityCentre/windows_event_logging/blob/59041b5d4586789a751171fb752be1624ad5e3b4/events/wmi_auditing/wmi_auditing.ps1'
    $rows = @(
        @('root\cimv2', 262146, 64, 'S-1-1-0'),
        @('root\cimv2', 1, 64, 'S-1-5-4'),
        @('root\cimv2', 1, 64, 'S-1-5-2'),
        @('root\cimv2', 1, 64, 'S-1-5-3'),
        @('root\SecurityCenter', 262145, 66, 'S-1-1-0'),
        @('root\SecurityCenter2', 262145, 66, 'S-1-1-0'),
        @('root\subscription', 262174, 66, 'S-1-1-0'),
        @('root\default', 262175, 66, 'S-1-1-0')
    )
    foreach ($selected in $Namespace) {
        if ($selected -notin @($rows | ForEach-Object { $_[0] })) { throw "Unsupported namespace '$selected'. Select exact local namespaces listed by wmi-auditing -WmiAction List; wildcards and remote paths are not accepted." }
    }
    foreach ($row in $rows) {
        if ($Namespace -and $row[0] -notin $Namespace) { continue }
        [pscustomobject][ordered]@{ Namespace = $row[0]; AccessMask = [uint32]$row[1]; AceType = 2
            AceFlags = $(if ($IncludeChildren) { [uint32]$row[2] } else { [uint32]64 }); Sid = $row[3]
            SourceAceFlags = $row[2]; Source = $source; AuditOutcome = 'Success'
            Scope = $(if ($IncludeChildren -and $row[2] -eq 66) { 'Selected namespace and inheriting descendants' } else { 'Selected namespace only' }) }
    }
}

function Initialize-WelaWmiInterop {
    if ($env:OS -ne 'Windows_NT') { throw 'WMI namespace security requires Windows.' }
    Add-Type -AssemblyName System.Management -ErrorAction Stop
    if ('Wela.WmiSecurityPrivilege' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace Wela {
 public sealed class WmiSecurityPrivilege : IDisposable {
  [StructLayout(LayoutKind.Sequential)] struct Luid { public uint Low; public int High; }
  [StructLayout(LayoutKind.Sequential)] struct TokenPrivileges { public uint Count; public Luid Luid; public uint Attributes; }
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool LookupPrivilegeValue(string system, string name, out Luid luid);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token, bool disable, ref TokenPrivileges current, uint size, out TokenPrivileges previous, out uint required);
  IntPtr token; TokenPrivileges previous; bool changed;
  public WmiSecurityPrivilege() {
   if (!OpenProcessToken(GetCurrentProcess(), 0x28, out token)) throw new Win32Exception(Marshal.GetLastWin32Error());
   try {
    Luid luid;
    if (!LookupPrivilegeValue(null, "SeSecurityPrivilege", out luid)) throw new Win32Exception(Marshal.GetLastWin32Error());
    TokenPrivileges requested = new TokenPrivileges { Count=1, Luid=luid, Attributes=2 };
    uint required;
    bool ok = AdjustTokenPrivileges(token, false, ref requested, (uint)Marshal.SizeOf(typeof(TokenPrivileges)), out previous, out required);
    int error = Marshal.GetLastWin32Error();
    if (!ok || error != 0) throw new Win32Exception(error, "SeSecurityPrivilege must be assigned and enabled; refusing a potentially incomplete SACL read.");
    changed=true;
   } catch { CloseHandle(token); token=IntPtr.Zero; throw; }
  }
  public void Dispose() {
   if (token==IntPtr.Zero) return;
   try {
    if (changed) {
     TokenPrivileges ignored; uint required;
     bool ok = AdjustTokenPrivileges(token, false, ref previous, (uint)Marshal.SizeOf(typeof(TokenPrivileges)), out ignored, out required);
     int error = Marshal.GetLastWin32Error();
     if (!ok || error != 0) throw new Win32Exception(error, "Restoring SeSecurityPrivilege failed; the previous token state could not be verified.");
    }
   } finally { CloseHandle(token); token=IntPtr.Zero; }
  }
 }
}
'@ -ErrorAction Stop
}

function Assert-WelaWmiReturnCode {
    param($Response, [string]$Method)
    if ($null -eq $Response -or $null -eq $Response.ReturnValue -or
        $Response.ReturnValue -is [bool] -or [string]$Response.ReturnValue -notmatch '^\d+$' -or
        [uint64]$Response.ReturnValue -ne 0) {
        throw "$Method failed (ReturnValue=$($Response.ReturnValue)); success requires an explicit numeric zero."
    }
}

function ConvertTo-WelaWmiData {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Management.ManagementBaseObject]) {
        $properties = [ordered]@{}
        foreach ($property in @($Value.Properties | Sort-Object Name)) { $properties[$property.Name] = ConvertTo-WelaWmiData $property.Value }
        return [pscustomobject]$properties
    }
    if ($Value -is [array]) {
        $items = @(); foreach ($item in $Value) { $items += ,(ConvertTo-WelaWmiData $item) }
        return ,$items
    }
    return $Value
}

function ConvertTo-WelaWmiJson { param($Value) ConvertTo-Json -InputObject $Value -Depth 40 -Compress }

function Get-WelaWmiSid {
    param($Trustee)
    if ($Trustee.SIDString) { return [string]$Trustee.SIDString }
    $bytes = [byte[]]$Trustee.SID
    if (-not $bytes -or $bytes.Length -lt 8 -or $bytes.Length -ne (8 + 4 * $bytes[1])) { return '' }
    [uint64]$authority = 0
    for ($i = 2; $i -lt 8; $i++) { $authority = ($authority * 256) + $bytes[$i] }
    $sid = "S-$($bytes[0])-$authority"
    for ($i = 0; $i -lt $bytes[1]; $i++) { $sid += '-' + [BitConverter]::ToUInt32($bytes, 8 + 4 * $i) }
    return $sid
}

function Test-WelaWmiAceMatch {
    param($Ace, $Definition)
    # Only an exact, explicit, ordinary success ACE satisfies a requested entry.
    # Unknown/object/inherited ACEs are retained without interpreting them.
    return $null -ne $Ace -and $Ace.AceType -eq 2 -and $Ace.AceFlags -eq $Definition.AceFlags -and
        $Ace.AccessMask -eq $Definition.AccessMask -and -not $Ace.GuidObjectType -and -not $Ace.GuidInheritedObjectType -and
        (Get-WelaWmiSid $Ace.Trustee) -eq $Definition.Sid
}

function Get-WelaWmiMissingAces {
    param($Descriptor, [array]$Definitions)
    foreach ($definition in $Definitions) {
        $matches = @($Descriptor.SACL | Where-Object { Test-WelaWmiAceMatch $_ $definition })
        if ($matches.Count -eq 0) { $definition }
    }
}

function New-WelaWmiConnection {
    param([string]$Namespace)
    $options = New-Object System.Management.ConnectionOptions
    # The caller already enables exactly SeSecurityPrivilege and restores it.
    # Automatic WMI privilege enabling can leave unrelated privileges enabled
    # on a thread impersonation token (observed SeBackupPrivilege on hosted CI).
    $options.EnablePrivileges = $false
    $options.Impersonation = [System.Management.ImpersonationLevel]::Impersonate
    $scope = New-Object System.Management.ManagementScope -ArgumentList "\\.\$Namespace", $options
    $scope.Connect()
    $path = New-Object System.Management.ManagementPath -ArgumentList '__SystemSecurity=@'
    return New-Object System.Management.ManagementObject -ArgumentList $scope, $path, $null
}

function Get-WelaWmiNativeDescriptor {
    param($Connection)
    $result = $Connection.InvokeMethod('GetSecurityDescriptor', $null, $null)
    Assert-WelaWmiReturnCode $result 'GetSecurityDescriptor'
    if ($null -eq $result.Descriptor -or $null -eq $result.Descriptor.ControlFlags) { throw 'GetSecurityDescriptor returned no complete descriptor.' }
    return $result.Descriptor
}

function Get-WelaWmiNamespaceSnapshot {
    param([string]$Namespace)
    Initialize-WelaWmiInterop
    $privilege = New-Object Wela.WmiSecurityPrivilege
    $connection = $null
    try {
        $connection = New-WelaWmiConnection $Namespace
        $descriptor = Get-WelaWmiNativeDescriptor $connection
        $data = ConvertTo-WelaWmiData $descriptor
        # Strings prevent JSON journal depth truncation of nested, unfamiliar ACEs.
        [pscustomobject]@{ Namespace = $Namespace; DescriptorJson = ConvertTo-WelaWmiJson $data
            DescriptorMof = $descriptor.GetText([System.Management.TextFormat]::Mof); SaclReadPrivilege = 'SeSecurityPrivilege enabled' }
    } finally {
        try { if ($connection) { $connection.Dispose() } }
        finally { $privilege.Dispose() }
    }
}

function Set-WelaWmiNamespaceDescriptor {
    param([string]$Namespace, [string]$ExpectedJson, [array]$Definitions)
    Initialize-WelaWmiInterop
    $privilege = New-Object Wela.WmiSecurityPrivilege
    $connection = $null
    try {
        $connection = New-WelaWmiConnection $Namespace
        $descriptor = Get-WelaWmiNativeDescriptor $connection
        $data = ConvertTo-WelaWmiData $descriptor
        if ((ConvertTo-WelaWmiJson $data) -cne $ExpectedJson) { throw 'Namespace descriptor changed after its recovery snapshot; no SACL was written. Review and retry.' }
        $missing = @(Get-WelaWmiMissingAces $data $Definitions)
        if (-not $missing.Count) { return 'Requested audit ACEs already present at the immediate pre-write read.' }
        # Clone the full native descriptor; existing native ACE objects are not
        # reconstructed from selected fields, merged, reordered, or removed.
        $updated = $descriptor.Clone()
        $aces = @($descriptor.SACL | Where-Object { $null -ne $_ })
        foreach ($definition in $missing) {
            $aceClass = New-Object System.Management.ManagementClass -ArgumentList '\\.\root\cimv2:Win32_ACE'
            $trusteeClass = New-Object System.Management.ManagementClass -ArgumentList '\\.\root\cimv2:Win32_Trustee'
            try {
                $ace = $aceClass.CreateInstance(); $trustee = $trusteeClass.CreateInstance()
                $sid = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $definition.Sid
                $sidBytes = New-Object byte[] $sid.BinaryLength; $sid.GetBinaryForm($sidBytes, 0)
                $trustee.SID = $sidBytes
                $ace.Trustee = $trustee; $ace.AccessMask = [uint32]$definition.AccessMask
                $ace.AceFlags = [uint32]$definition.AceFlags; $ace.AceType = [uint32]2
                $aces += $ace
            } finally { $aceClass.Dispose(); $trusteeClass.Dispose() }
        }
        $updated.SACL = [System.Management.ManagementBaseObject[]]$aces
        # SetSecurityDescriptor treats SE_DACL_PRESENT and non-null Owner/Group
        # as requests to rewrite access permissions. Omit those fields explicitly
        # so the provider preserves them, even if another writer races this call.
        # Complete original fields remain in the journal and read-back comparison.
        $updated.DACL = $null; $updated.Owner = $null; $updated.Group = $null
        $updated.ControlFlags = ([uint32]$descriptor.ControlFlags -band [uint32]4294967291) -bor [uint32]16
        $parameters = $connection.GetMethodParameters('SetSecurityDescriptor')
        $parameters.Descriptor = $updated
        $response = $connection.InvokeMethod('SetSecurityDescriptor', $parameters, $null)
        Assert-WelaWmiReturnCode $response 'SetSecurityDescriptor'
        'SACL update accepted; full descriptor preservation and audit entries require read-back verification. Event generation is unverified.'
    } finally {
        try { if ($connection) { $connection.Dispose() } }
        finally { $privilege.Dispose() }
    }
}

function Test-WelaWmiDescriptorPreserved {
    param($Before, $After)
    foreach ($property in $Before.PSObject.Properties) {
        if ($property.Name -eq 'SACL') { continue }
        if ($property.Name -eq 'ControlFlags') {
            if ([uint32]$After.ControlFlags -ne ([uint32]$Before.ControlFlags -bor 16)) { return $false }
        } elseif ((ConvertTo-WelaWmiJson $property.Value) -cne (ConvertTo-WelaWmiJson $After.($property.Name))) { return $false }
    }
    # Compare a multiset: providers can reorder a SACL, but cannot remove/change
    # any original entry, including unknown types, trustee details or extra fields.
    $remaining = New-Object 'System.Collections.Generic.List[string]'
    foreach ($ace in @($After.SACL)) { if ($null -ne $ace) { $remaining.Add((ConvertTo-WelaWmiJson $ace)) } }
    foreach ($ace in @($Before.SACL)) {
        if ($null -eq $ace) { continue }
        if (-not $remaining.Remove((ConvertTo-WelaWmiJson $ace))) { return $false }
    }
    return $true
}

function Get-WelaWmiNamespaceInventory {
    $namespaces = @(Get-WelaWmiAuditDefinitions | Select-Object -ExpandProperty Namespace -Unique)
    try {
        $children = @(Get-CimInstance -Namespace root -ClassName __Namespace -ErrorAction Stop | ForEach-Object { 'root\' + $_.Name })
        foreach ($namespace in $namespaces) { [pscustomobject]@{ Namespace = $namespace; State = $(if ($namespace -in $children) { 'Present' } else { 'NotInstalled' }) } }
    } catch {
        foreach ($namespace in $namespaces) { [pscustomobject]@{ Namespace = $namespace; State = 'Unknown'; Diagnostic = $_.Exception.Message } }
    }
}

function Get-WelaWmiAuditPrerequisite {
    try {
        $mask = Get-WelaNativeAuditPolicy -Guid '0CCE9227-69AE-11D9-BED3-505054503030'
        [pscustomobject]@{ Policy = 'Other Object Access Events'; Mask = $mask; SuccessEnabled = (($mask -band 1) -eq 1); State = 'Observed' }
    } catch { [pscustomobject]@{ Policy = 'Other Object Access Events'; Mask = $null; SuccessEnabled = $null; State = 'Unknown'; Diagnostic = $_.Exception.Message } }
}

function Get-WelaWmiAuditPlan {
    param([string[]]$Namespace, [switch]$IncludeChildren)
    if (-not $Namespace.Count) { throw 'Select at least one exact namespace with -WmiNamespace; there is no implicit all-namespaces configuration.' }
    $definitions = @(Get-WelaWmiAuditDefinitions -Namespace $Namespace -IncludeChildren:$IncludeChildren)
    foreach ($name in @($definitions | Select-Object -ExpandProperty Namespace -Unique)) {
        $selected = @($definitions | Where-Object Namespace -eq $name)
        try {
            $snapshot = Get-WelaWmiNamespaceSnapshot $name
            $descriptor = $snapshot.DescriptorJson | ConvertFrom-Json
            $missing = @(Get-WelaWmiMissingAces $descriptor $selected)
            [pscustomobject]@{ Namespace = $name; Status = $(if ($missing.Count) { 'ChangeRequired' } else { 'AlreadyCompliant' }); Before = $snapshot; Definitions = $selected; Missing = $missing; Diagnostic = '' }
        } catch { [pscustomobject]@{ Namespace = $name; Status = 'Unknown'; Before = $null; Definitions = $selected; Missing = @(); Diagnostic = $_.Exception.Message } }
    }
}

function Set-WelaWmiAuditControls {
    param($Context, [array]$Plan)
    foreach ($entry in $Plan) {
        $callback = @{ Namespace = $entry.Namespace; Definitions = $entry.Definitions; Original = $null; ExpectedJson = $null; Applied = $false; VerifiedJson = $null }
        $read = {
            param($state)
            $snapshot = Get-WelaWmiNamespaceSnapshot $state.Namespace
            if ($null -eq $state.Original) { $state.Original = $snapshot.DescriptorJson | ConvertFrom-Json; $state.ExpectedJson = $snapshot.DescriptorJson }
            return $snapshot
        }
        $test = {
            param($snapshot, $state)
            $descriptor = $snapshot.DescriptorJson | ConvertFrom-Json
            if (@(Get-WelaWmiMissingAces $descriptor $state.Definitions).Count) { return $false }
            if ($state.Applied) {
                if (-not (Test-WelaWmiDescriptorPreserved $state.Original $descriptor)) { return $false }
                if ($null -eq $state.VerifiedJson) { $state.VerifiedJson = $snapshot.DescriptorJson }
                return $snapshot.DescriptorJson -ceq $state.VerifiedJson
            }
            # An already compliant descriptor still gets a full final drift check.
            return $snapshot.DescriptorJson -ceq $state.ExpectedJson
        }
        $apply = {
            param($state)
            Set-WelaWmiNamespaceDescriptor -Namespace $state.Namespace -ExpectedJson $state.ExpectedJson -Definitions $state.Definitions
            $state.Applied = $true
        }
        Invoke-WelaConfigurationControl -Context $Context -Id "WmiNamespace/$($entry.Namespace)/SACL" -Kind WmiNamespaceSacl `
            -Target @{ Namespace = $entry.Namespace; Computer = 'Local'; Operation = 'Append audit ACEs only' } -Desired $entry.Definitions `
            -Read $read -Compliant $test -Apply $apply -CallbackState $callback `
            -Description ('Append missing success audit ACEs. Scope: ' + (($entry.Definitions.Scope | Select-Object -Unique) -join ', '))
    }
}

function Invoke-WelaWmiAuditCommand {
    param([ValidateSet('List', 'Audit', 'Plan', 'Configure')][string]$Action = 'List', [string[]]$Namespace,
          [switch]$IncludeChildren, [switch]$Auto, [switch]$DryRun, [string]$BackupPath, [string]$ResultsPath)
    if ($env:OS -ne 'Windows_NT') { throw 'WMI namespace auditing requires Windows.' }
    if ($DryRun -and $Action -ne 'Configure') { throw '-DryRun requires -WmiAction Configure.' }
    if ($Action -eq 'List') {
        if ($Namespace -or $IncludeChildren) { throw 'List does not accept namespace or inheritance selections. Use Audit, Plan or Configure.' }
        $inventory = @(Get-WelaWmiNamespaceInventory)
        $report = [pscustomobject]@{ Scope = 'wmi-namespace-sacl-only'; Action = $Action; Namespaces = $inventory; ExitCode = $(if (@($inventory | Where-Object State -eq Unknown).Count) { 1 } else { 0 }) }
    } else {
        $plan = @(Get-WelaWmiAuditPlan -Namespace $Namespace -IncludeChildren:$IncludeChildren)
        $prerequisite = Get-WelaWmiAuditPrerequisite
        if ($Action -eq 'Configure') {
            $context = New-WelaConfigurationContext -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath
            Set-WelaWmiAuditControls -Context $context -Plan $plan
            $report = Complete-WelaConfiguration -Context $context -Scope 'wmi-namespace-sacl-only' `
                -SuccessMessage 'Selected WMI namespace SACLs verified; namespace access events and collection remain unverified.'
            $report | Add-Member NoteProperty Prerequisite $prerequisite
        } else { $report = [pscustomobject]@{ Scope = 'wmi-namespace-sacl-only'; Action = $Action; Controls = $plan; Prerequisite = $prerequisite; ExitCode = $(if (@($plan | Where-Object Status -eq Unknown).Count) { 1 } else { 0 }) } }
        $report | Add-Member NoteProperty EventValidation 'Not performed. Namespace access auditing (Security 4662) is distinct from provider-operation success and local/remote WMI-Activity telemetry. Audit-policy readiness is observed separately; no usable-rule credit.'
    }
    if ($ResultsPath) {
        try { $report | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $ResultsPath -Encoding UTF8 -ErrorAction Stop }
        catch { $report.ExitCode = 1; Write-Host "[Failed] Writing WMI results: $_" -ForegroundColor Red }
    }
    return $report
}
