# Explicit, additive AD DS audit ACEs. No AD: drive, server discovery, or DACL writes.
function Search-WelaAdDirectory {
    param($Session, [string]$Dn, [string]$Filter = '(objectClass=*)', [string]$Scope = 'Base',
          [string[]]$Attributes, [switch]$SecurityDescriptor)
    $request = [System.DirectoryServices.Protocols.SearchRequest]::new($Dn, $Filter,
        [System.DirectoryServices.Protocols.SearchScope]::$Scope, $Attributes)
    if ($SecurityDescriptor) {
        $control = [System.DirectoryServices.Protocols.SecurityDescriptorFlagControl]::new(
            [System.DirectoryServices.Protocols.SecurityMasks]15)
        $control.IsCritical = $true
        $null = $request.Controls.Add($control)
    }
    $response = $Session.Connection.SendRequest($request)
    foreach ($entry in $response.Entries) {
        $values = @{}
        foreach ($name in $entry.Attributes.AttributeNames) {
            $type = if ($name -in @('nTSecurityDescriptor', 'objectGUID', 'schemaIDGUID')) { [byte[]] } else { [string] }
            $values[$name] = $entry.Attributes[$name].GetValues($type)
        }
        [pscustomobject]@{ Dn = $entry.DistinguishedName; Values = $values }
    }
}

function Get-WelaAdSingleValue {
    param($Entry, [string]$Name)
    if (-not $Entry.Values.ContainsKey($Name) -or @($Entry.Values[$Name]).Count -ne 1) {
        throw "Required AD attribute is missing or ambiguous: $Name ($($Entry.Dn))."
    }
    return ,$Entry.Values[$Name][0]
}

function New-WelaAdConnection {
    param([string]$Server)
    Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop
    $identifier = [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($Server, 389, $true, $false)
    $connection = [System.DirectoryServices.Protocols.LdapConnection]::new($identifier)
    try {
        $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
        $connection.Timeout = [TimeSpan]::FromSeconds(30)
        $connection.SessionOptions.ProtocolVersion = 3
        $connection.SessionOptions.Signing = $true
        $connection.SessionOptions.Sealing = $true
        $connection.SessionOptions.ReferralChasing = [System.DirectoryServices.Protocols.ReferralChasingOptions]::None
        return $connection
    } catch { $connection.Dispose(); throw }
}

function Open-WelaAdSession {
    param([string]$Server)
    if ($env:OS -ne 'Windows_NT') { throw 'AD object SACL operations require Windows PowerShell 5.1 or PowerShell 7 on Windows.' }
    if ($Server -notmatch '^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$') {
        throw 'AdServer must be the exact DNS host name of one DC (FQDN), without a port, path, or LDAP URL.'
    }
    $connection = New-WelaAdConnection $Server
    try {
        $connection.Bind()
        $session = [pscustomobject]@{ Server = $Server; Connection = $connection; DomainDn = ''; ConfigurationDn = ''; SchemaDn = ''; DsaDn = ''; Writable = $false }
        $root = @(Search-WelaAdDirectory -Session $session -Dn '' -Attributes @('dnsHostName', 'defaultNamingContext', 'configurationNamingContext', 'schemaNamingContext', 'dsServiceName', 'supportedCapabilities', 'supportedControl'))
        if ($root.Count -ne 1) { throw 'RootDSE was not returned uniquely.' }
        if ((Get-WelaAdSingleValue $root[0] 'dnsHostName') -ine $Server) { throw 'RootDSE dnsHostName differs from AdServer; aliases and domain-wide targets are refused.' }
        if ($root[0].Values['supportedCapabilities'] -notcontains '1.2.840.113556.1.4.800' -or
            $root[0].Values['supportedControl'] -notcontains '1.2.840.113556.1.4.801') { throw 'AD DS and the security-descriptor flags control must be supported.' }
        $session.DomainDn = Get-WelaAdSingleValue $root[0] 'defaultNamingContext'
        $session.ConfigurationDn = Get-WelaAdSingleValue $root[0] 'configurationNamingContext'
        $session.SchemaDn = Get-WelaAdSingleValue $root[0] 'schemaNamingContext'
        $session.DsaDn = Get-WelaAdSingleValue $root[0] 'dsServiceName'
        $dsa = @(Search-WelaAdDirectory -Session $session -Dn $session.DsaDn -Attributes @('msDS-isRODC'))
        if ($dsa.Count -ne 1 -or (Get-WelaAdSingleValue $dsa[0] 'msDS-isRODC') -notin @('TRUE', 'FALSE')) { throw 'DC write capability is unknown.' }
        $session.Writable = (Get-WelaAdSingleValue $dsa[0] 'msDS-isRODC') -eq 'FALSE'
        return $session
    } catch { $connection.Dispose(); throw }
}

function Get-WelaAdAuditDefinitions {
    # Exact masks in Microsoft's Test-MdiReadiness at 730dad6870154279b6c41009c9ebab84ffa24689.
    $classes = @(
        @('user', 'bf967aba-0de6-11d0-a285-00aa003049e2', 852331),
        @('group', 'bf967a9c-0de6-11d0-a285-00aa003049e2', 852331),
        @('computer', 'bf967a86-0de6-11d0-a285-00aa003049e2', 852331),
        @('msDS-ManagedServiceAccount', 'ce206244-5827-4a86-ba1c-1c0c386c1b64', 852331),
        @('msDS-GroupManagedServiceAccount', '7b8b558a-93a5-4af7-adca-c017e67f1057', 852075),
        @('msDS-DelegatedManagedServiceAccount', '0feb936f-47b3-49f2-9386-1dedc2c23765', 852075)
    )
    foreach ($item in $classes) {
        [pscustomobject]@{ Class = $item[0]; Sid = 'S-1-1-0'; AccessMask = $item[2]; AuditFlags = 'Success'; AceFlags = 74;
            ObjectType = [guid]::Empty.ToString(); InheritedObjectType = $item[1]; Inheritance = 'DescendantsOnly';
            Rights = 'CreateChild, DeleteChild, Self, WriteProperty, DeleteTree, Delete, WriteDacl, WriteOwner' + $(if ($item[2] -eq 852331) { ', ExtendedRight' } else { '' }) }
    }
}

function Test-WelaAdSchemaClass {
    param($Session, [string]$Class, [string]$Guid)
    # Class is from our fixed allowlist, never user-provided LDAP filter text.
    $rows = @(Search-WelaAdDirectory -Session $Session -Dn $Session.SchemaDn -Scope OneLevel -Filter "(&(objectClass=classSchema)(lDAPDisplayName=$Class))" -Attributes @('schemaIDGUID'))
    if ($rows.Count -eq 0) { return $false }
    if ($rows.Count -ne 1 -or ([guid]::new([byte[]](Get-WelaAdSingleValue $rows[0] 'schemaIDGUID'))).ToString() -ne $Guid) {
        throw "Schema GUID mismatch or ambiguous class: $Class."
    }
    return $true
}

function Test-WelaAdDmsaDomain {
    param($Session)
    $rows = @(Search-WelaAdDirectory -Session $Session -Dn $Session.DomainDn -Scope Subtree -Filter '(&(objectClass=computer)(primaryGroupID=516))' -Attributes @('operatingSystemVersion'))
    if (-not $rows.Count) { throw 'No domain controller computer versions were readable for the dMSA applicability check.' }
    $unknown = $false
    foreach ($row in $rows) {
        if (-not $row.Values.ContainsKey('operatingSystemVersion')) { $unknown = $true; continue }
        $version = [string](Get-WelaAdSingleValue $row 'operatingSystemVersion')
        if ($version -match '^10\.0\s*\((\d+)\)$') { if ([int]$Matches[1] -ge 26100) { return $true } }
        else { $unknown = $true }
    }
    if ($unknown) { throw 'DC versions could not all be classified; dMSA applicability is unknown.' }
    return $false
}

function ConvertTo-WelaAdBinaryString {
    param($Object)
    if ($null -eq $Object) { return $null }
    $bytes = New-Object byte[] $Object.BinaryLength
    $Object.GetBinaryForm($bytes, 0)
    return [Convert]::ToBase64String($bytes)
}

function New-WelaAdAuditAce {
    param($Definition)
    $sid = [Security.Principal.SecurityIdentifier]::new($Definition.Sid)
    if ($Definition.InheritedObjectType -ne [guid]::Empty.ToString()) {
        return [Security.AccessControl.ObjectAce]::new([Security.AccessControl.AceFlags]$Definition.AceFlags,
            [Security.AccessControl.AceQualifier]::SystemAudit, [int]$Definition.AccessMask, $sid,
            [Security.AccessControl.ObjectAceFlags]::InheritedObjectAceTypePresent, [guid]::Empty,
            [guid]$Definition.InheritedObjectType, $false, $null)
    }
    return [Security.AccessControl.CommonAce]::new([Security.AccessControl.AceFlags]$Definition.AceFlags,
        [Security.AccessControl.AceQualifier]::SystemAudit, [int]$Definition.AccessMask, $sid, $false, $null)
}

function Get-WelaAdDescriptorInfo {
    param([string]$Binary)
    $sd = [Security.AccessControl.RawSecurityDescriptor]::new([Convert]::FromBase64String($Binary), 0)
    $aces = @(); if ($sd.SystemAcl) { foreach ($ace in $sd.SystemAcl) { $aces += ConvertTo-WelaAdBinaryString $ace } }
    [pscustomobject]@{ Binary = $Binary; Sddl = $sd.GetSddlForm([Security.AccessControl.AccessControlSections]::All);
        Owner = [string]$sd.Owner; Group = [string]$sd.Group; Dacl = ConvertTo-WelaAdBinaryString $sd.DiscretionaryAcl;
        ControlFlags = [int]$sd.ControlFlags; Sacl = $aces }
}

function Get-WelaAdObjectState {
    param($Session, [string]$Dn)
    $rows = @(Search-WelaAdDirectory -Session $Session -Dn $Dn -Attributes @('nTSecurityDescriptor', 'objectGUID', 'uSNChanged', 'objectClass') -SecurityDescriptor)
    if ($rows.Count -ne 1) { throw "AD object missing or ambiguous: $Dn." }
    $binary = [Convert]::ToBase64String([byte[]](Get-WelaAdSingleValue $rows[0] 'nTSecurityDescriptor'))
    $info = Get-WelaAdDescriptorInfo $binary
    [pscustomobject]@{ Server = $Session.Server; Dn = $rows[0].Dn;
        ObjectGuid = ([guid]::new([byte[]](Get-WelaAdSingleValue $rows[0] 'objectGUID'))).ToString();
        UsnChanged = [string](Get-WelaAdSingleValue $rows[0] 'uSNChanged'); Classes = @($rows[0].Values['objectClass']); Descriptor = $info }
}

function Test-WelaAdAcePresent {
    param($Descriptor, $Definition)
    $wanted = New-WelaAdAuditAce $Definition
    foreach ($encoded in $Descriptor.Sacl) {
        $ace = [Security.AccessControl.GenericAce]::CreateFromBinaryForm([Convert]::FromBase64String($encoded), 0)
        # Accept an existing audit ACE granting a superset of the required audited
        # rights/outcomes, but only with the exact inheritance and object scope.
        if ($ace -isnot [Security.AccessControl.QualifiedAce] -or $ace.IsCallback -or $ace.AceQualifier -ne $wanted.AceQualifier -or
            $ace.SecurityIdentifier -ne $wanted.SecurityIdentifier -or ($ace.AccessMask -band $wanted.AccessMask) -ne $wanted.AccessMask) { continue }
        if (([int]$ace.AceFlags -band 63) -ne ([int]$wanted.AceFlags -band 63) -or
            ([int]$ace.AceFlags -band [int]$wanted.AceFlags) -ne [int]$wanted.AceFlags) { continue }
        if ($wanted -is [Security.AccessControl.ObjectAce]) {
            if ($ace -isnot [Security.AccessControl.ObjectAce] -or $ace.ObjectAceFlags -ne $wanted.ObjectAceFlags -or
                $ace.ObjectAceType -ne $wanted.ObjectAceType -or $ace.InheritedObjectAceType -ne $wanted.InheritedObjectAceType) { continue }
        } elseif ($ace -is [Security.AccessControl.ObjectAce] -and [int]$ace.ObjectAceFlags -ne 0) { continue }
        return $true
    }
    return $false
}

function New-WelaAdSaclAddition {
    param($Before, [array]$Definitions)
    $sd = [Security.AccessControl.RawSecurityDescriptor]::new([Convert]::FromBase64String($Before.Descriptor.Binary), 0)
    $oldCount = if ($sd.SystemAcl) { $sd.SystemAcl.Count } else { 0 }
    $acl = [Security.AccessControl.RawAcl]::new([byte]4, $oldCount + $Definitions.Count)
    if ($sd.SystemAcl) { foreach ($ace in $sd.SystemAcl) { $acl.InsertAce($acl.Count, $ace) } }
    $added = @()
    foreach ($definition in $Definitions) {
        if (Test-WelaAdAcePresent $Before.Descriptor $definition) { continue }
        $ace = New-WelaAdAuditAce $definition
        # Insert explicit ACEs before inherited ACEs; preserve every existing ACE.
        $position = 0
        while ($position -lt $acl.Count -and -not $acl[$position].IsInherited) { $position++ }
        $acl.InsertAce($position, $ace)
        $added += ConvertTo-WelaAdBinaryString $ace
    }
    $sd.SystemAcl = $acl
    $sd.SetFlags($sd.ControlFlags -bor [Security.AccessControl.ControlFlags]::SystemAclPresent)
    [pscustomobject]@{ Binary = ConvertTo-WelaAdBinaryString $sd; AddedAces = $added }
}

function Test-WelaAdPreserved {
    param($Before, $After)
    if ($Before.ObjectGuid -ne $After.ObjectGuid -or $Before.Server -ine $After.Server -or $Before.Dn -ine $After.Dn -or
        $Before.Descriptor.Owner -ne $After.Descriptor.Owner -or $Before.Descriptor.Group -ne $After.Descriptor.Group -or
        $Before.Descriptor.Dacl -ne $After.Descriptor.Dacl -or
        ($Before.Descriptor.ControlFlags -band 65519) -ne ($After.Descriptor.ControlFlags -band 65519)) { return $false }
    $remaining = New-Object 'System.Collections.Generic.List[string]'
    foreach ($ace in $After.Descriptor.Sacl) { $remaining.Add($ace) }
    foreach ($ace in $Before.Descriptor.Sacl) { if (-not $remaining.Remove($ace)) { return $false } }
    return $true
}

function Write-WelaAdSacl {
    param($Session, [string]$Dn, [string]$Binary)
    if (-not $Session.Writable) { throw 'The explicitly selected DC is read-only; no write was sent.' }
    $modification = [System.DirectoryServices.Protocols.DirectoryAttributeModification]::new()
    $modification.Name = 'nTSecurityDescriptor'
    $modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
    $null = $modification.Add([Convert]::FromBase64String($Binary))
    $request = [System.DirectoryServices.Protocols.ModifyRequest]::new($Dn, $modification)
    # The DC modifies SACL only. Owner/group/DACL are never sent as a requested change.
    $control = [System.DirectoryServices.Protocols.SecurityDescriptorFlagControl]::new([System.DirectoryServices.Protocols.SecurityMasks]::Sacl)
    $control.IsCritical = $true
    $null = $request.Controls.Add($control)
    $null = $Session.Connection.SendRequest($request)
}

function Test-WelaAdPkiContainer {
    param($Session, $Snapshot, [string]$ContainerDn)
    # A one-level GUID lookup proves parent membership without interpreting DN
    # text (escaped commas can otherwise impersonate an approved suffix).
    $escapedGuid = (([guid]$Snapshot.ObjectGuid).ToByteArray() | ForEach-Object { '\{0:X2}' -f $_ }) -join ''
    $rows = @(Search-WelaAdDirectory -Session $Session -Dn $ContainerDn -Scope OneLevel `
        -Filter "(objectGUID=$escapedGuid)" -Attributes @('objectGUID'))
    if ($rows.Count -eq 0) { return $false }
    if ($rows.Count -ne 1 -or $rows[0].Dn -ine $Snapshot.Dn -or
        ([guid]::new([byte[]](Get-WelaAdSingleValue $rows[0] 'objectGUID'))).ToString() -ne $Snapshot.ObjectGuid) {
        throw 'PKI container membership lookup returned an unexpected object identity.'
    }
    return $true
}

function Get-WelaAdSaclPlan {
    param($Session, [string[]]$Profiles, [string[]]$ObjectDn)
    $requests = @()
    if ($Profiles -contains 'MdiDomain') { $requests += [pscustomobject]@{ Profile = 'MdiDomain'; Dn = $Session.DomainDn } }
    if ($Profiles -contains 'MdiConfiguration') { $requests += [pscustomobject]@{ Profile = 'MdiConfiguration'; Dn = $Session.ConfigurationDn } }
    if ($Profiles -contains 'PkiObjects') {
        if (-not $ObjectDn.Count) { throw 'PkiObjects requires explicit -AdObjectDn certificate template or enrollment service object DNs.' }
        foreach ($dn in @($ObjectDn | Select-Object -Unique)) { $requests += [pscustomobject]@{ Profile = 'PkiObjects'; Dn = $dn } }
    } elseif ($ObjectDn.Count) { throw '-AdObjectDn is valid only with the PkiObjects profile.' }
    foreach ($request in $requests) {
        $definitions = @(); $skippedDefinitions = @(); $before = $null; $notes = @(); $status = 'Unknown'
        try {
            if ($request.Profile -eq 'MdiDomain') {
                foreach ($definition in Get-WelaAdAuditDefinitions) {
                    if ($definition.Class -eq 'msDS-DelegatedManagedServiceAccount') {
                        # dMSA is conditional. Its unknown schema/DC prerequisites
                        # must not prevent the five independent class ACEs.
                        $prerequisiteStatus = 'Applicable'; $diagnostic = ''
                        try {
                            $exists = Test-WelaAdSchemaClass $Session $definition.Class $definition.InheritedObjectType
                            if (-not $exists -or -not (Test-WelaAdDmsaDomain $Session)) {
                                $prerequisiteStatus = 'NotApplicable'
                                $diagnostic = 'dMSA skipped: schema class and a domain DC version >= 10.0 (26100) are required.'
                            }
                        } catch {
                            $prerequisiteStatus = 'Unknown'
                            $diagnostic = "dMSA skipped: prerequisite Unknown ($($_.Exception.Message)). dMSA auditing is not established; the other five class ACEs remain independent."
                        }
                        if ($prerequisiteStatus -ne 'Applicable') {
                            $notes += $diagnostic
                            $skippedDefinitions += [pscustomobject]@{ Definition = $definition; Status = 'Skipped'; PrerequisiteStatus = $prerequisiteStatus; Diagnostic = $diagnostic }
                            continue
                        }
                    } elseif (-not (Test-WelaAdSchemaClass $Session $definition.Class $definition.InheritedObjectType)) {
                        throw "Required MDI schema class is absent: $($definition.Class)."
                    }
                    $definitions += $definition
                }
            } elseif ($request.Profile -eq 'MdiConfiguration') {
                $exchange = @(Search-WelaAdDirectory -Session $Session -Dn $Session.ConfigurationDn -Scope Subtree -Filter '(objectClass=msExchOrganizationContainer)' -Attributes @('objectClass'))
                if (-not $exchange.Count) { $status = 'NotApplicable'; throw 'No Exchange organization container observed. MDI Configuration auditing is intended for current or former Exchange deployments; review removed-history cases manually.' }
                $definitions = @([pscustomobject]@{ Class = ''; Sid = 'S-1-1-0'; AccessMask = 32; AuditFlags = 'Success, Failure'; AceFlags = 194; ObjectType = [guid]::Empty.ToString(); InheritedObjectType = [guid]::Empty.ToString(); Inheritance = 'ThisObjectAndAllDescendants'; Rights = 'WriteProperty' })
            } else {
                $before = Get-WelaAdObjectState $Session $request.Dn
                $class = $null; $guid = $null
                if ($before.Classes -contains 'pKICertificateTemplate' -and
                    (Test-WelaAdPkiContainer $Session $before "CN=Certificate Templates,CN=Public Key Services,CN=Services,$($Session.ConfigurationDn)")) {
                    $class = 'pKICertificateTemplate'; $guid = 'e5209ca2-3bba-11d2-90cc-00c04fd91ab1'
                } elseif ($before.Classes -contains 'pKIEnrollmentService' -and
                    (Test-WelaAdPkiContainer $Session $before "CN=Enrollment Services,CN=Public Key Services,CN=Services,$($Session.ConfigurationDn)")) {
                    $class = 'pKIEnrollmentService'; $guid = 'ee4aa692-3bba-11d2-90cc-00c04fd91ab1'
                } else { throw 'PkiObjects accepts only existing certificate template/enrollment service objects under the selected forest PKI containers.' }
                if (-not (Test-WelaAdSchemaClass $Session $class $guid)) { throw "PKI schema class missing: $class." }
                $definitions = @([pscustomobject]@{ Class = $class; Sid = 'S-1-1-0'; AccessMask = 852000; AuditFlags = 'Success'; AceFlags = 64; ObjectType = [guid]::Empty.ToString(); InheritedObjectType = [guid]::Empty.ToString(); Inheritance = 'ThisObjectOnly'; Rights = 'WriteProperty, Delete, WriteDacl, WriteOwner' })
                $notes += 'WELA targeted PKI profile, not an MDI-prescribed PKI baseline; no child objects, enrollment rights or CA AuditFilter changes.'
            }
            if (-not $before) { $before = Get-WelaAdObjectState $Session $request.Dn }
            $missing = @($definitions | Where-Object { -not (Test-WelaAdAcePresent $before.Descriptor $_) })
            $status = if ($missing.Count) { 'ChangeRequired' } else { 'SaclConfigured' }
            if (-not $Session.Writable -and $missing.Count) { $status = 'Blocked'; $notes += 'Selected DC is read-only.' }
        } catch { $notes += $_.Exception.Message }
        [pscustomobject]@{ Profile = $request.Profile; Server = $Session.Server; Dn = $request.Dn; Status = $status;
            Definitions = $definitions; SkippedDefinitions = $skippedDefinitions; Before = $before; Diagnostic = $notes -join ' ' }
    }
}

function Set-WelaAdSaclControls {
    param($Session, $Context, [array]$Plan)
    foreach ($entry in $Plan) {
        $id = "AdSacl/$($entry.Profile)/$($entry.Dn)"
        foreach ($skipped in $entry.SkippedDefinitions) {
            $Context.Results.Add([pscustomobject]@{ Id = "$id/$($skipped.Definition.Class)/Prerequisite"; Kind = 'AdObjectSaclPrerequisite';
                Target = @{ Server = $Session.Server; Dn = $entry.Dn; Class = $skipped.Definition.Class }; Desired = $skipped.Definition;
                Before = $null; After = $null; Status = 'Skipped'; PrerequisiteStatus = $skipped.PrerequisiteStatus; Diagnostic = $skipped.Diagnostic })
            Write-Host "[Skipped] $id/$($skipped.Definition.Class) $($skipped.Diagnostic)" -ForegroundColor Yellow
        }
        if ($entry.Status -notin @('SaclConfigured', 'ChangeRequired')) {
            $Context.Results.Add([pscustomobject]@{ Id = $id; Kind = 'AdObjectSacl'; Target = @{ Server = $Session.Server; Dn = $entry.Dn }; Desired = $entry.Definitions;
                Before = $entry.Before; After = $null; Status = $(if ($entry.Status -eq 'NotApplicable') { 'Skipped' } else { 'Failed' }); Diagnostic = $entry.Diagnostic })
            continue
        }
        $state = @{ Session = $Session; Entry = $entry; Observed = $null; Baseline = $null; Context = $Context }
        $read = {
            param($state)
            $snapshot = Get-WelaAdObjectState $state.Session $state.Entry.Dn
            if ($snapshot.ObjectGuid -ne $state.Entry.Before.ObjectGuid) { throw 'Target object identity changed after planning.' }
            if ($state.Baseline -and -not (Test-WelaAdPreserved $state.Baseline $snapshot)) { throw 'Existing owner, group, DACL or SACL ACE changed; inspect the recovery journal. No automatic restore is attempted.' }
            $state.Observed = $snapshot
            return $snapshot
        }
        $test = { param($snapshot, $state)
            foreach ($definition in $state.Entry.Definitions) { if (-not (Test-WelaAdAcePresent $snapshot.Descriptor $definition)) { return $false } }
            return $true
        }
        $apply = {
            param($state)
            $before = $state.Observed
            $addition = New-WelaAdSaclAddition $before $state.Entry.Definitions
            $receipt = [ordered]@{ Version = 1; Kind = 'WelaAdSaclAddition'; ReceiptStatus = 'Pending'; Server = $state.Session.Server; Dn = $before.Dn;
                ObjectGuid = $before.ObjectGuid; Before = $before; AddedAces = $addition.AddedAces; ExpectedBinary = $addition.Binary;
                ConfirmedUtc = $null; ConfirmedAfter = $null }
            # Durable intent precedes mutation, but cannot authorize rollback.
            # A failed/stale request may never have written its intended ACEs.
            $receiptPath = Join-Path $state.Context.BackupPath ('ad-sacl-' + [guid]::NewGuid().ToString('N') + '.json')
            $receipt | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $receiptPath -Encoding UTF8 -ErrorAction Stop
            $fresh = Get-WelaAdObjectState $state.Session $state.Entry.Dn
            if ($fresh.ObjectGuid -ne $before.ObjectGuid -or $fresh.UsnChanged -ne $before.UsnChanged -or $fresh.Descriptor.Binary -ne $before.Descriptor.Binary) { throw 'AD object changed after journaling; no write was sent. Re-audit and retry.' }
            $state.Baseline = $before
            Write-WelaAdSacl $state.Session $before.Dn $addition.Binary
            $verified = Get-WelaAdObjectState $state.Session $before.Dn
            if (-not (Test-WelaAdPreserved $before $verified)) { throw 'Existing owner, group, DACL or SACL ACE changed after writing; receipt remains Pending and requires manual recovery review.' }
            foreach ($definition in $state.Entry.Definitions) {
                if (-not (Test-WelaAdAcePresent $verified.Descriptor $definition)) { throw 'Requested SACL did not verify after writing; receipt remains Pending and requires manual recovery review.' }
            }
            $receipt.ReceiptStatus = 'Confirmed'
            $receipt.ConfirmedUtc = [DateTime]::UtcNow.ToString('o')
            $receipt.ConfirmedAfter = $verified
            $confirmedPath = $receiptPath + '.tmp'
            $receipt | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $confirmedPath -Encoding UTF8 -ErrorAction Stop
            # Preserve the complete Pending receipt if confirmation cannot persist.
            [IO.File]::Replace($confirmedPath, $receiptPath, ($receiptPath + '.pending'))
            "SACL-only write and read-back verified; confirmed recovery receipt: $receiptPath. Event generation and inheritance propagation remain unverified."
        }
        Invoke-WelaConfigurationControl -Context $Context -Id $id -Kind AdObjectSacl -Target @{ Server = $Session.Server; Dn = $entry.Dn } `
            -Desired $entry.Definitions -Read $read -Compliant $test -Apply $apply -CallbackState $state `
            -Description 'Add only missing audit ACEs on this exact DC/object. Directory auditing may increase event volume.'
    }
}

function Invoke-WelaAdSaclRollback {
    param($Session, $Context, [string]$ReceiptPath)
    $receipt = Get-Content -LiteralPath $ReceiptPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($receipt.Version -ne 1 -or $receipt.Kind -ne 'WelaAdSaclAddition' -or $receipt.Server -ine $Session.Server -or
        -not $receipt.AddedAces.Count -or $receipt.ObjectGuid -ne $receipt.Before.ObjectGuid -or $receipt.Dn -ine $receipt.Before.Dn) { throw 'Invalid receipt, empty additions, or a different DC target.' }
    if ($receipt.ReceiptStatus -ne 'Confirmed' -or -not $receipt.ConfirmedUtc -or
        $receipt.ConfirmedAfter.ObjectGuid -ne $receipt.ObjectGuid -or $receipt.ConfirmedAfter.Server -ine $Session.Server -or
        $receipt.ConfirmedAfter.Dn -ine $receipt.Dn) { throw 'Unconfirmed receipt: automatic rollback cannot establish ACE ownership. Review Pending/failed/interrupted changes manually.' }
    $expected = Get-WelaAdDescriptorInfo $receipt.ExpectedBinary
    # Receipts are recovery evidence, not a general descriptor-restore mechanism.
    $remaining = New-Object 'System.Collections.Generic.List[string]'
    foreach ($ace in $expected.Sacl) { $remaining.Add($ace) }
    foreach ($ace in $receipt.AddedAces) { if (-not $remaining.Remove([string]$ace)) { throw 'Receipt additions do not match its expected SACL.' } }
    if (($remaining.ToArray() -join '|') -ne (@($receipt.Before.Descriptor.Sacl) -join '|')) { throw 'Receipt would remove or replace pre-existing audit ACEs.' }
    $state = @{ Session = $Session; Receipt = $receipt; Observed = $null; Expected = $expected; Baseline = $null }
    $read = { param($state)
        $snapshot = Get-WelaAdObjectState $state.Session $state.Receipt.Dn
        if ($snapshot.ObjectGuid -ne $state.Receipt.ObjectGuid) { throw 'Rollback object identity mismatch.' }
        if ($state.Baseline -and ($snapshot.Descriptor.Owner -ne $state.Baseline.Descriptor.Owner -or
            $snapshot.Descriptor.Group -ne $state.Baseline.Descriptor.Group -or $snapshot.Descriptor.Dacl -ne $state.Baseline.Descriptor.Dacl -or
            $snapshot.Descriptor.ControlFlags -ne $state.Baseline.Descriptor.ControlFlags)) { throw 'Owner/group/DACL/descriptor flags changed during rollback; inspect the journal.' }
        $state.Observed = $snapshot
        return $snapshot
    }
    $test = { param($snapshot, $state)
        return (@($snapshot.Descriptor.Sacl) -join '|') -eq (@($state.Receipt.Before.Descriptor.Sacl) -join '|')
    }
    $apply = { param($state)
        $before = $state.Observed
        if ((@($before.Descriptor.Sacl) -join '|') -ne (@($state.Expected.Sacl) -join '|')) { throw 'SACL drift or ACE merging makes ownership ambiguous; automated rollback refused.' }
        $fresh = Get-WelaAdObjectState $state.Session $state.Receipt.Dn
        if ($fresh.UsnChanged -ne $before.UsnChanged -or $fresh.ObjectGuid -ne $before.ObjectGuid -or $fresh.Descriptor.Binary -ne $before.Descriptor.Binary) { throw 'Object changed before rollback; no write sent.' }
        $sd = [Security.AccessControl.RawSecurityDescriptor]::new([Convert]::FromBase64String($fresh.Descriptor.Binary), 0)
        for ($i = $sd.SystemAcl.Count - 1; $i -ge 0; $i--) {
            $encoded = ConvertTo-WelaAdBinaryString $sd.SystemAcl[$i]
            if ($state.Receipt.AddedAces -contains $encoded) { $sd.SystemAcl.RemoveAce($i) }
        }
        $state.Baseline = $fresh
        Write-WelaAdSacl $state.Session $state.Receipt.Dn (ConvertTo-WelaAdBinaryString $sd)
        'Removed only exact receipt-owned audit ACEs; no owner/group/DACL restoration performed.'
    }
    Invoke-WelaConfigurationControl -Context $Context -Id "AdSaclRollback/$($receipt.Dn)" -Kind AdObjectSaclRollback `
        -Target @{ Server = $Session.Server; Dn = $receipt.Dn } -Desired @{ RemoveExactAces = $receipt.AddedAces } `
        -Read $read -Compliant $test -Apply $apply -CallbackState $state -Description 'Remove only the exact audit ACE additions from this trusted receipt.'
}

function Invoke-WelaAdSaclCommand {
    param([ValidateSet('Audit', 'Plan', 'Configure', 'Rollback')][string]$Action = 'Audit', [string]$Server,
          [ValidateSet('MdiDomain', 'MdiConfiguration', 'PkiObjects')][string[]]$Profiles, [string[]]$ObjectDn,
          [string]$ReceiptPath, [switch]$Auto, [switch]$DryRun, [string]$BackupPath, [string]$ResultsPath)
    if ($DryRun -and $Action -notin @('Configure', 'Rollback')) { throw 'DryRun applies only to Configure or Rollback.' }
    if ($Action -eq 'Rollback') {
        if (-not $ReceiptPath -or $Profiles.Count -or $ObjectDn.Count) { throw 'Rollback requires AdReceiptPath and no profile/object selection.' }
    } elseif (-not $Profiles.Count -or $ReceiptPath) { throw 'Select at least one explicit AdSaclProfile; AdReceiptPath is for Rollback only.' }
    $session = Open-WelaAdSession $Server
    try {
        $plan = @()
        if ($Action -ne 'Rollback') { $plan = @(Get-WelaAdSaclPlan $session $Profiles $ObjectDn) }
        if ($Action -in @('Configure', 'Rollback')) {
            $context = New-WelaConfigurationContext -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath
            if ($Action -eq 'Rollback') { Invoke-WelaAdSaclRollback $session $context $ReceiptPath }
            else { Set-WelaAdSaclControls $session $context $plan }
            $report = Complete-WelaConfiguration -Context $context -Scope 'ad-object-sacl-only' `
                -SuccessMessage 'Requested SACL state verified on the selected DC; audit policy, inherited propagation and event generation remain separate checks.'
        } else {
            $report = [pscustomobject]@{ ExitCode = $(if (@($plan | Where-Object Status -in @('Unknown', 'Blocked')).Count) { 1 } else { 0 }); Scope = 'ad-object-sacl-only'; Results = $plan }
        }
        $report | Add-Member NoteProperty Server $session.Server
        $report | Add-Member NoteProperty Action $Action
        $report | Add-Member NoteProperty AuditPolicyPrerequisites @(
            [pscustomobject]@{ Name = 'Directory Service Access'; Guid = '0cce923b-69ae-11d9-bed3-505054503030'; Required = 'Success (Failure also required for Configuration failure auditing)'; Status = 'Unknown'; Diagnostic = 'Remote DC audit policy is not read or changed by this LDAP command.' },
            [pscustomobject]@{ Name = 'Directory Service Changes'; Guid = '0cce923c-69ae-11d9-bed3-505054503030'; Required = 'Success'; Status = 'Unknown'; Diagnostic = 'Verify effective policy and 5136 on the DC handling the object change.' })
        $report | Add-Member NoteProperty VerificationScope 'Selected-DC object SACL state only. Skipped or Unknown class prerequisites do not establish auditing for those classes. Inherited child SACLs, protected objects, policy, 4662/5136 generation, replication and collection are unverified. No Sigma uplift is claimed.'
        if ($ResultsPath) { $report | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $ResultsPath -Encoding UTF8 -ErrorAction Stop }
        return $report
    } finally { $session.Connection.Dispose() }
}
