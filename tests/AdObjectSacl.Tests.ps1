$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$script:ScriptRoot = $repo
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/AdObjectSacl.ps1')
$script:checks = 0
function Assert($Condition, [string]$Message) { if (-not $Condition) { throw "FAIL: $Message" }; $script:checks++ }
function Assert-Throws([scriptblock]$Action, [string]$Message) { $thrown = $false; try { & $Action } catch { $thrown = $true }; Assert $thrown $Message }
$root = Join-Path ([IO.Path]::GetTempPath()) ('wela-ad-sacl-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $root
$session = [pscustomobject]@{ Server = 'dc1.example.test'; DomainDn = 'DC=example,DC=test'; ConfigurationDn = 'CN=Configuration,DC=example,DC=test'; SchemaDn = 'CN=Schema,CN=Configuration,DC=example,DC=test'; Writable = $true }
$script:originalDmsa = ${function:Test-WelaAdDmsaDomain}
$script:originalSchema = ${function:Test-WelaAdSchemaClass}
$script:originalRead = ${function:Get-WelaAdObjectState}
$script:originalSearch = ${function:Search-WelaAdDirectory}
$script:originalPresent = ${function:Test-WelaAdAcePresent}
$script:originalAddition = ${function:New-WelaAdSaclAddition}
$script:originalWrite = ${function:Write-WelaAdSacl}
$script:originalInfo = ${function:Get-WelaAdDescriptorInfo}
function Reset-Mocks {
    $script:writes = 0; $script:reads = 0; $script:readError = $false; $script:writeError = $false
    $script:race = $false; $script:finalDrift = $false; $script:badReadback = $false; $script:removeExisting = $false
    $script:absentClass = ''; $script:dmsa = $true; $script:exchange = $true; $script:onPrompt = $null; $script:pkiMember = $true; $script:pkiRequest = $null
    $script:state = [pscustomobject]@{ Server = $session.Server; Dn = $session.DomainDn; ObjectGuid = '01234567-89ab-cdef-0123-456789abcdef'; UsnChanged = '17'; Classes = @('top', 'domainDNS');
        Descriptor = [pscustomobject]@{ Binary = 'before'; Sddl = 'O:SYG:SYD:(A;;GA;;;SY)S:(AU;SA;WP;;;BA)'; Owner = 'S-1-5-18'; Group = 'S-1-5-18'; Dacl = 'unchanged-dacl'; ControlFlags = 32788; Sacl = @('unrelated') } }
    $session.Writable = $true
}
function Test-WelaAdSchemaClass { param($Session, $Class, $Guid) return $Class -ne $script:absentClass }
function Test-WelaAdDmsaDomain { param($Session) return $script:dmsa }
function Search-WelaAdDirectory {
    param($Session, $Dn, $Filter, $Scope, $Attributes, [switch]$SecurityDescriptor)
    if ($Filter -eq '(objectClass=msExchOrganizationContainer)' -and $script:exchange) { [pscustomobject]@{ Dn = 'CN=Exchange'; Values = @{} } }
    if ($Filter -like '(objectGUID=*') {
        $script:pkiRequest = @{ Dn = $Dn; Scope = $Scope; Filter = $Filter }
        if ($script:pkiMember) { [pscustomobject]@{ Dn = $script:state.Dn; Values = @{ objectGUID = @(,([guid]$script:state.ObjectGuid).ToByteArray()) } } }
    }
}
function Get-WelaAdObjectState {
    param($Session, $Dn)
    $script:reads++
    if ($script:readError) { throw 'LDAP access denied' }
    $snapshot = $script:state | ConvertTo-Json -Depth 10 | ConvertFrom-Json
    if ($script:race -and $script:reads -ge 3) { $snapshot.UsnChanged = '99' }
    if ($script:finalDrift -and $script:reads -ge 6) { $snapshot.Descriptor.Sacl = @('unrelated'); $snapshot.Descriptor.Binary = 'drift' }
    return $snapshot
}
function Test-WelaAdAcePresent { param($Descriptor, $Definition) return $Descriptor.Sacl -contains ('added-' + $Definition.Class) }
function New-WelaAdSaclAddition {
    param($Before, $Definitions)
    [pscustomobject]@{ Binary = 'after'; AddedAces = @($Definitions | Where-Object { -not (Test-WelaAdAcePresent $Before.Descriptor $_) } | ForEach-Object { 'added-' + $_.Class }) }
}
function Write-WelaAdSacl {
    param($Session, $Dn, $Binary)
    if ($script:writeError) { throw 'LDAP insufficientAccessRights' }
    $script:writes++
    if (-not $script:badReadback) {
        $script:state.Descriptor.Sacl = @('unrelated') + @(Get-WelaAdAuditDefinitions | ForEach-Object { 'added-' + $_.Class })
        $script:state.Descriptor.Binary = $Binary
    }
    if ($script:removeExisting) { $script:state.Descriptor.Sacl = @($script:state.Descriptor.Sacl | Where-Object { $_ -ne 'unrelated' }) }
    $script:state.UsnChanged = '18'
}
function Read-Host { param($Prompt) if ($script:onPrompt) { & $script:onPrompt }; return 'y' }
function Get-Context([bool]$Dry = $false, [bool]$Automatic = $true) {
    New-WelaConfigurationContext -Auto:$Automatic -DryRun:$Dry -BackupPath (Join-Path $root ([guid]::NewGuid().ToString('N')))
}
function Invoke-TestConfigure($Context) {
    $plan = @(Get-WelaAdSaclPlan $session @('MdiDomain') @())
    Set-WelaAdSaclControls $session $Context $plan
    Complete-WelaConfiguration -Context $Context -Scope ad-object-sacl-only
}
try {
    $defs = @(Get-WelaAdAuditDefinitions)
    Assert ($defs.Count -eq 6) 'all six MDI descendant classes are defined'
    Assert ((@($defs.AccessMask) -join ',') -eq '852331,852331,852331,852331,852075,852075') 'exact Microsoft readiness masks, including gMSA/dMSA distinction'
    Assert (@($defs | Where-Object { $_.Sid -ne 'S-1-1-0' -or $_.AceFlags -ne 74 -or $_.Inheritance -ne 'DescendantsOnly' -or $_.ObjectType -ne [guid]::Empty.ToString() }).Count -eq 0) 'success, descendant-only, unrestricted property scope is explicit'
    Assert (($defs.InheritedObjectType | Select-Object -Unique).Count -eq 6) 'all inherited class GUIDs differ'
    Reset-Mocks
    $plan = @(Get-WelaAdSaclPlan $session @('MdiDomain') @())
    Assert ($plan.Count -eq 1 -and $plan[0].Definitions.Count -eq 6 -and $plan[0].Status -eq 'ChangeRequired') 'domain plan covers exact root'
    Assert ($plan[0].Server -eq $session.Server -and $plan[0].Dn -eq $session.DomainDn) 'plan binds exact server and DN'
    $script:dmsa = $false
    $plan = @(Get-WelaAdSaclPlan $session @('MdiDomain') @())
    Assert ($plan[0].Definitions.Count -eq 5 -and $plan[0].Diagnostic -like '*dMSA skipped*') 'dMSA omitted without a 2025 domain DC'
    $script:absentClass = 'user'
    Assert ((@(Get-WelaAdSaclPlan $session @('MdiDomain') @()))[0].Status -eq 'Unknown') 'missing required class blocks writes'
    Reset-Mocks; $script:exchange = $false
    Assert ((@(Get-WelaAdSaclPlan $session @('MdiConfiguration') @()))[0].Status -eq 'NotApplicable') 'configuration gated on Exchange history evidence'
    $script:exchange = $true
    $plan = @(Get-WelaAdSaclPlan $session @('MdiConfiguration') @())
    Assert ($plan[0].Definitions[0].AccessMask -eq 32 -and $plan[0].Definitions[0].AceFlags -eq 194) 'Configuration WriteProperty success/failure inheritance is exact'
    Assert-Throws { Get-WelaAdSaclPlan $session @('PkiObjects') @() } 'PKI requires explicit target DNs'
    $script:state.Dn = "CN=Test,CN=Certificate Templates,CN=Public Key Services,CN=Services,$($session.ConfigurationDn)"
    $script:state.Classes = @('top', 'pKICertificateTemplate')
    $plan = @(Get-WelaAdSaclPlan $session @('PkiObjects') @($script:state.Dn))
    Assert ($plan[0].Status -eq 'ChangeRequired' -and $plan[0].Definitions[0].AccessMask -eq 852000 -and $plan[0].Definitions[0].AceFlags -eq 64) 'PKI direct-object write/delete/ACL audit only'
    Assert ($script:pkiRequest.Scope -eq 'OneLevel' -and $script:pkiRequest.Dn -eq "CN=Certificate Templates,CN=Public Key Services,CN=Services,$($session.ConfigurationDn)" -and
        $script:pkiRequest.Filter -eq '(objectGUID=\67\45\23\01\AB\89\EF\CD\01\23\45\67\89\AB\CD\EF)') 'PKI membership uses exact parent and byte-escaped object GUID'
    $script:pkiMember = $false
    $script:state.Dn = "CN=Test,$($session.DomainDn)"
    Assert ((@(Get-WelaAdSaclPlan $session @('PkiObjects') @($script:state.Dn)))[0].Status -eq 'Unknown') 'PKI class outside trusted forest containers refused'
    $script:state.Dn = "CN=Foo\,CN=Certificate Templates,CN=Public Key Services,CN=Services,$($session.ConfigurationDn)"
    Assert ((@(Get-WelaAdSaclPlan $session @('PkiObjects') @($script:state.Dn)))[0].Status -eq 'Unknown') 'escaped RDN suffix cannot impersonate approved PKI parent'
    Reset-Mocks; $session.Writable = $false
    Assert ((@(Get-WelaAdSaclPlan $session @('MdiDomain') @()))[0].Status -eq 'Blocked') 'RODC plan explicitly blocked'
    Reset-Mocks; $script:readError = $true
    $ctx = Get-Context; $report = Invoke-TestConfigure $ctx
    Assert ($report.ExitCode -eq 1 -and $script:writes -eq 0) 'access denied is failed/unknown, never an empty descriptor'
    Reset-Mocks; $ctx = Get-Context $true
    $report = Invoke-TestConfigure $ctx
    Assert ($report.DryRun -and $script:writes -eq 0 -and -not (Test-Path $ctx.BackupPath)) 'dry run does not write AD or journal'
    Reset-Mocks; $ctx = Get-Context
    $report = Invoke-TestConfigure $ctx
    Assert ($report.ExitCode -eq 0 -and $report.Results[0].Status -eq 'Applied' -and $script:writes -eq 1) 'additive apply and final verification succeed'
    $journal = Get-Content (Join-Path $ctx.BackupPath 'before.jsonl') | ConvertFrom-Json
    Assert ($journal.Before.Descriptor.Sddl -like 'O:SY*' -and $journal.Before.ObjectGuid -eq $script:state.ObjectGuid) 'journal contains original SDDL and identity'
    $receipts = @(Get-ChildItem $ctx.BackupPath -Filter 'ad-sacl-*.json')
    $receipt = Get-Content $receipts[0].FullName -Raw | ConvertFrom-Json
    Assert ($receipt.AddedAces.Count -eq 6 -and $receipt.Before.Descriptor.Binary -eq 'before') 'receipt stores only intended additions and before binary'
    Assert ($receipt.ReceiptStatus -eq 'Confirmed' -and $receipt.ConfirmedAfter.Descriptor.Binary -eq 'after' -and $receipt.ConfirmedUtc) 'successful write and readback confirm rollback ownership'
    $ctx2 = Get-Context; $report2 = Invoke-TestConfigure $ctx2
    Assert ($script:writes -eq 1 -and $report2.Results[0].Status -eq 'AlreadyCompliant') 'repeat run is idempotent'
    Reset-Mocks; $script:race = $true; $ctx = Get-Context
    $report = Invoke-TestConfigure $ctx
    Assert ($report.ExitCode -eq 1 -and $script:writes -eq 0 -and $report.Results[0].Diagnostic -like '*changed after journaling*') 'USN race fails closed before write'
    $pendingPath = @(Get-ChildItem $ctx.BackupPath -Filter 'ad-sacl-*.json')[0].FullName
    Assert ((Get-Content $pendingPath -Raw | ConvertFrom-Json).ReceiptStatus -eq 'Pending') 'stale pre-write receipt remains pending'
    $script:state.Descriptor.Sacl = @('unrelated') + @(Get-WelaAdAuditDefinitions | ForEach-Object { 'added-' + $_.Class })
    $script:state.Descriptor.Binary = 'after'
    Assert-Throws { Invoke-WelaAdSaclRollback $session (Get-Context $true) $pendingPath } 'pending intent cannot authorize rollback of another writers matching ACEs'
    Reset-Mocks; $script:writeError = $true; $ctx = Get-Context
    $report = Invoke-TestConfigure $ctx
    $pendingPath = @(Get-ChildItem $ctx.BackupPath -Filter 'ad-sacl-*.json')[0].FullName
    Assert ($report.ExitCode -eq 1 -and (Get-Content $pendingPath -Raw | ConvertFrom-Json).ReceiptStatus -eq 'Pending') 'failed LDAP write cannot confirm receipt'
    Assert-Throws { Invoke-WelaAdSaclRollback $session (Get-Context $true) $pendingPath } 'failed-write receipt cannot authorize automatic rollback'
    Reset-Mocks; $script:badReadback = $true; $ctx = Get-Context
    Assert ((Invoke-TestConfigure $ctx).ExitCode -eq 1) 'missing audit ACE readback fails'
    $pendingPath = @(Get-ChildItem $ctx.BackupPath -Filter 'ad-sacl-*.json')[0].FullName
    Assert ((Get-Content $pendingPath -Raw | ConvertFrom-Json).ReceiptStatus -eq 'Pending') 'failed readback leaves receipt pending'
    Reset-Mocks; $script:removeExisting = $true; $ctx = Get-Context
    $report = Invoke-TestConfigure $ctx
    Assert ($report.ExitCode -eq 1 -and $report.Results[0].Diagnostic -like '*Existing owner*') 'loss of pre-existing audit ACE fails verification'
    Reset-Mocks; $script:finalDrift = $true; $ctx = Get-Context
    $report = Invoke-TestConfigure $ctx
    Assert ($report.ExitCode -eq 1 -and $report.Results[0].Status -eq 'Overridden') 'later missing WELA ACEs are overridden'
    Reset-Mocks; $ctx = Get-Context $false $false
    $script:onPrompt = { Remove-Item -LiteralPath $ctx.BackupPath -Recurse -Force }
    $report = Invoke-TestConfigure $ctx
    Assert ($report.ExitCode -eq 1 -and $script:writes -eq 0) 'journal failure prevents mutation'

    # Test schema and DC eligibility adapters with controlled directory responses.
    Set-Item function:Test-WelaAdDmsaDomain $script:originalDmsa
    function Search-WelaAdDirectory { param($Session, $Dn, $Filter, $Scope, $Attributes)
        [pscustomobject]@{ Dn = 'CN=DC1'; Values = @{ operatingSystemVersion = @($script:version) } }
    }
    $script:version = '10.0 (20348)'; Assert (-not (Test-WelaAdDmsaDomain $session)) 'Server 2022 is not dMSA eligible'
    $script:version = '10.0 (26100)'; Assert (Test-WelaAdDmsaDomain $session) 'Server 2025 version proves dMSA applicability'
    $script:version = 'unreadable'; Assert-Throws { Test-WelaAdDmsaDomain $session } 'unknown DC versions remain unknown'
    Set-Item function:Test-WelaAdSchemaClass $script:originalSchema
    function Search-WelaAdDirectory { param($Session, $Dn, $Filter, $Scope, $Attributes)
        [pscustomobject]@{ Dn = 'CN=User'; Values = @{ schemaIDGUID = @(,([guid]$script:schemaGuid).ToByteArray()) } }
    }
    $script:schemaGuid = $defs[0].InheritedObjectType
    Assert (Test-WelaAdSchemaClass $session user $script:schemaGuid) 'schema binary GUID checked'
    Assert-Throws { Test-WelaAdSchemaClass $session user $defs[1].InheritedObjectType } 'unexpected schema GUID rejected'

    # RootDSE binding validation with a fully fake connection: no platform/native calls.
    $savedOs = $env:OS
    try {
        $env:OS = 'Windows_NT'; $script:rootHost = 'dc1.example.test'; $script:rodc = 'FALSE'; $script:disposed = 0
        function New-WelaAdConnection { param($Server)
            $fake = [pscustomobject]@{}
            $fake | Add-Member ScriptMethod Bind { }
            $fake | Add-Member ScriptMethod Dispose { $script:disposed++ }
            return $fake
        }
        function Search-WelaAdDirectory { param($Session, $Dn, $Filter, $Scope, $Attributes)
            if ($Dn -eq '') {
                [pscustomobject]@{ Dn = ''; Values = @{ dnsHostName = @($script:rootHost); defaultNamingContext = @('DC=example,DC=test');
                    configurationNamingContext = @('CN=Configuration,DC=example,DC=test'); schemaNamingContext = @('CN=Schema,CN=Configuration,DC=example,DC=test');
                    dsServiceName = @('CN=NTDS Settings,CN=DC1'); supportedCapabilities = @('1.2.840.113556.1.4.800'); supportedControl = @('1.2.840.113556.1.4.801') } }
            } else { [pscustomobject]@{ Dn = $Dn; Values = @{ 'msDS-isRODC' = @($script:rodc) } } }
        }
        $bound = Open-WelaAdSession 'dc1.example.test'
        Assert ($bound.Writable -and $bound.Server -eq 'dc1.example.test') 'RootDSE confirms exact selected writable DC'
        $script:rodc = 'TRUE'; Assert (-not (Open-WelaAdSession 'dc1.example.test').Writable) 'RootDSE RODC capability remains read-only'
        $script:rootHost = 'dc2.example.test'
        Assert-Throws { Open-WelaAdSession 'dc1.example.test' } 'wrong RootDSE host fails closed'
        Assert ($script:disposed -eq 1) 'failed binding validation disposes connection'
        Assert-Throws { Open-WelaAdSession 'LDAP://dc1.example.test' } 'LDAP URLs are not accepted as exact DC names'
    } finally { $env:OS = $savedOs }

    # No network is ever used. Native SID/ACL APIs are exercised in the Windows suite.
    $tokens = $null; $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'WELA.ps1'), [ref]$tokens, [ref]$errors)
    Assert ($errors.Count -eq 0) 'WELA entry point parses'
    Write-Host "Passed $script:checks AD object SACL mocked assertions. No live AD connection or mutation occurred."
} finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
