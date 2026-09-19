# Offline fixtures and captured LDAP requests only. Never bind to or modify AD.
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { Write-Host 'Skipped: native Windows SID/ACL APIs required.'; exit 0 }
$repo = Split-Path $PSScriptRoot -Parent
$script:ScriptRoot = $repo
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/AdObjectSacl.ps1')
Add-Type -AssemblyName System.DirectoryServices.Protocols
$script:checks = 0
function Assert($Condition, [string]$Message) { if (-not $Condition) { throw "FAIL: $Message" }; $script:checks++ }
function Assert-Throws([scriptblock]$Action, [string]$Message) { $thrown = $false; try { & $Action } catch { $thrown = $true }; Assert $thrown $Message }
function New-State([string]$Sddl) {
    $sd = [Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
    [pscustomobject]@{ Server = 'dc1.example.test'; Dn = 'DC=example,DC=test'; ObjectGuid = '01234567-89ab-cdef-0123-456789abcdef'; UsnChanged = '100'; Descriptor = Get-WelaAdDescriptorInfo (ConvertTo-WelaAdBinaryString $sd) }
}
$root = Join-Path ([IO.Path]::GetTempPath()) ('wela-ad-native-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $root
try {
    $before = New-State 'O:SYG:BAD:PAI(A;;GA;;;SY)(A;;RP;;;BA)S:PAI(AU;SA;WP;;;BA)(AU;CISAID;RP;;;WD)'
    $definitions = @(Get-WelaAdAuditDefinitions)
    $addition = New-WelaAdSaclAddition $before $definitions
    Assert ($addition.AddedAces.Count -eq 6) 'adds six missing object-specific audit ACEs'
    $after = New-State $before.Descriptor.Sddl
    $after.Descriptor = Get-WelaAdDescriptorInfo $addition.Binary
    Assert (Test-WelaAdPreserved $before $after) 'preserves owner/group/DACL/flags and all pre-existing audit ACE bytes'
    foreach ($definition in $definitions) {
        Assert (Test-WelaAdAcePresent $after.Descriptor $definition) "exact class ACE found: $($definition.Class)"
        $ace = New-WelaAdAuditAce $definition
        Assert ($ace.AceType -eq [Security.AccessControl.AceType]::SystemAuditObject -and [int]$ace.AceFlags -eq 74 -and [int]$ace.ObjectAceFlags -eq 2) 'native object ACE has success and descendant-only flags'
        Assert ($ace.InheritedObjectAceType -eq [guid]$definition.InheritedObjectType -and $ace.ObjectAceType -eq [guid]::Empty) 'native inherited class GUID and unrestricted object/property GUID'
    }
    $second = New-WelaAdSaclAddition $after $definitions
    Assert ($second.AddedAces.Count -eq 0 -and $second.Binary -eq $addition.Binary) 'byte-identical second application'
    $empty = New-State 'O:SYG:SYD:(A;;GA;;;SY)'
    $emptyAfter = New-State $empty.Descriptor.Sddl
    $emptyAfter.Descriptor = Get-WelaAdDescriptorInfo (New-WelaAdSaclAddition $empty $definitions).Binary
    Assert (Test-WelaAdPreserved $empty $emptyAfter) 'adding first SACL preserves all non-SACL information'
    $superset = $definitions[0] | Select-Object *
    $superset.AccessMask = 983551; $superset.AceFlags = 202
    $broad = New-WelaAdSaclAddition $empty @($superset)
    Assert (Test-WelaAdAcePresent (Get-WelaAdDescriptorInfo $broad.Binary) $definitions[0]) 'same-scope Success+Failure superset avoids duplicate auditing'
    Assert (-not (Test-WelaAdAcePresent (Get-WelaAdDescriptorInfo $broad.Binary) $definitions[1])) 'wrong inherited class does not satisfy required ACE'
    $wrongScope = $definitions[0] | Select-Object *; $wrongScope.AceFlags = 66
    $scopeFixture = New-WelaAdSaclAddition $empty @($wrongScope)
    Assert (-not (Test-WelaAdAcePresent (Get-WelaAdDescriptorInfo $scopeFixture.Binary) $definitions[0])) 'different inheritance is not treated as exact scope'
    $config = [pscustomobject]@{ Sid = 'S-1-1-0'; AccessMask = 32; AceFlags = 194; InheritedObjectType = [guid]::Empty.ToString() }
    $configAce = New-WelaAdAuditAce $config
    Assert ($configAce.AceType -eq [Security.AccessControl.AceType]::SystemAudit -and [int]$configAce.AceFlags -eq 194) 'Configuration audit ACE success+failure this object and all descendants'
    $pki = [pscustomobject]@{ Sid = 'S-1-1-0'; AccessMask = 852000; AceFlags = 64; InheritedObjectType = [guid]::Empty.ToString() }
    $pkiAce = New-WelaAdAuditAce $pki
    Assert ($pkiAce.AccessMask -eq 852000 -and $pkiAce.InheritanceFlags -eq 'None') 'PKI direct-object permissions use no inheritance'

    # Construct native LDAP requests with a fake transport. No network call occurs.
    $connection = [pscustomobject]@{}
    $connection | Add-Member ScriptMethod SendRequest { param($Request) $script:captured = $Request; throw 'Captured offline' }
    $session = [pscustomobject]@{ Server = $before.Server; Writable = $true; Connection = $connection }
    Assert-Throws { Write-WelaAdSacl $session $before.Dn $addition.Binary } 'write request captured offline'
    Assert ($script:captured -is [System.DirectoryServices.Protocols.ModifyRequest] -and $script:captured.DistinguishedName -eq $before.Dn) 'exact DN in native modify request'
    Assert ($script:captured.Modifications.Count -eq 1 -and $script:captured.Modifications[0].Name -eq 'nTSecurityDescriptor') 'only security descriptor attribute is modified'
    Assert ($script:captured.Controls[0].SecurityMasks -eq [System.DirectoryServices.Protocols.SecurityMasks]::Sacl -and $script:captured.Controls[0].IsCritical) 'critical SACL-only write control'
    Assert-Throws { Search-WelaAdDirectory $session $before.Dn -Attributes @('nTSecurityDescriptor') -SecurityDescriptor } 'read request captured offline'
    Assert ($script:captured -is [System.DirectoryServices.Protocols.SearchRequest] -and [int]$script:captured.Controls[0].SecurityMasks -eq 15) 'read requests owner/group/DACL/SACL together'
    $session.Writable = $false; $script:captured = $null
    Assert-Throws { Write-WelaAdSacl $session $before.Dn $addition.Binary } 'RODC write refused'
    Assert ($null -eq $script:captured) 'RODC refusal happens before transport'

    # Mock the state/transport boundary, retain real ACL transformations and runner.
    $script:state = $after; $script:writes = 0
    function Get-WelaAdObjectState { param($Session, $Dn) return ($script:state | ConvertTo-Json -Depth 12 | ConvertFrom-Json) }
    function Write-WelaAdSacl { param($Session, $Dn, $Binary)
        $script:writes++; $script:state.Descriptor = Get-WelaAdDescriptorInfo $Binary; $script:state.UsnChanged = '101'
        if ($script:corruptRollback) { $script:state.Descriptor.Owner = 'S-1-5-19' }
    }
    $session.Writable = $true
    $receiptPath = Join-Path $root 'receipt.json'
    [pscustomobject]@{ Version = 1; Kind = 'WelaAdSaclAddition'; ReceiptStatus = 'Confirmed'; ConfirmedUtc = [DateTime]::UtcNow.ToString('o');
        ConfirmedAfter = $after; Server = $before.Server; Dn = $before.Dn; ObjectGuid = $before.ObjectGuid;
        Before = $before; AddedAces = $addition.AddedAces; ExpectedBinary = $addition.Binary } | ConvertTo-Json -Depth 12 | Set-Content $receiptPath -Encoding UTF8
    $ctx = New-WelaConfigurationContext -Auto -BackupPath (Join-Path $root 'rollback')
    Invoke-WelaAdSaclRollback $session $ctx $receiptPath
    $report = Complete-WelaConfiguration $ctx -Scope ad-object-sacl-only
    Assert ($report.ExitCode -eq 0 -and $script:writes -eq 1) 'rollback verified through runner'
    Assert (($script:state.Descriptor.Sacl -join '|') -eq ($before.Descriptor.Sacl -join '|')) 'rollback preserves all original ACEs and removes owned additions'
    Assert ($script:state.Descriptor.Dacl -eq $before.Descriptor.Dacl -and $script:state.Descriptor.Owner -eq $before.Descriptor.Owner) 'rollback never restores/replaces authorization data'
    $ctx = New-WelaConfigurationContext -Auto -BackupPath (Join-Path $root 'rollback-repeat')
    Invoke-WelaAdSaclRollback $session $ctx $receiptPath
    Assert ($ctx.Results[0].Status -eq 'AlreadyCompliant' -and $script:writes -eq 1) 'repeated rollback is idempotent'
    $script:state.Descriptor = Get-WelaAdDescriptorInfo $addition.Binary
    $withDrift = New-WelaAdSaclAddition $script:state @($config)
    $script:state.Descriptor = Get-WelaAdDescriptorInfo $withDrift.Binary
    $ctx = New-WelaConfigurationContext -Auto -BackupPath (Join-Path $root 'rollback-drift')
    Invoke-WelaAdSaclRollback $session $ctx $receiptPath
    Assert ($ctx.Results[0].Status -eq 'Failed' -and $script:writes -eq 1) 'rollback refuses ambiguous intervening SACL changes'
    $script:state.Descriptor = Get-WelaAdDescriptorInfo $addition.Binary
    $script:corruptRollback = $true
    $ctx = New-WelaConfigurationContext -Auto -BackupPath (Join-Path $root 'rollback-corruption')
    Invoke-WelaAdSaclRollback $session $ctx $receiptPath
    Assert ($ctx.Results[0].Status -eq 'Failed' -and $ctx.Results[0].Diagnostic -like '*Owner/group/DACL*') 'independent rollback snapshot detects owner corruption'
    Write-Host "Passed $script:checks native Windows AD descriptor/LDAP tests. No AD bind or live mutation occurred."
} finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
