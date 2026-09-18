# Native channel metadata and lossless, read-only ACL planning. Windows PowerShell 5.1.
function Get-WelaNativeChannelProfile {
    param([string]$Id = 'microsoft-wef-appendix-c')
    $profile = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../config/native_channel_profile.json') -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($Id -ne $profile.id -or $profile.schemaVersion -ne 1 -or $profile.scope -ne 'native-channel-settings-only') { throw "Unknown/invalid native channel profile '$Id'." }
    $names = @{}
    foreach ($control in $profile.controls) {
        if (-not $control.channel -or $control.channel -match '[*?\[\]\r\n]' -or $names.ContainsKey($control.channel)) { throw 'Invalid/duplicate native channel name.' }
        $names[$control.channel] = $true
        if ($null -ne $control.enabled -and ($control.enabled -isnot [bool] -or -not $control.enabled)) { throw 'Native channel profiles may only enable a channel or preserve its enabled state.' }
        if ($control.sourceExampleBytes -isnot [int] -and $control.sourceExampleBytes -isnot [long]) { throw 'Channel size must be an integer byte count.' }
        $null = ConvertTo-WelaEventLogBytes $control.sourceExampleBytes
        if ($control.readerSid -and ($control.readerSid -ne 'S-1-5-32-573' -or $control.readerMask -ne 1)) { throw 'Only the Event Log Readers read grant is supported.' }
    }
    foreach ($name in @('Baseline', 'Suspect')) {
        if (@($profile.querySets.$name.channels).Count -eq 0) { throw "Empty native WEF query inventory: $name" }
        foreach ($channel in $profile.querySets.$name.channels) {
            if (-not $channel.name -or $channel.name -match '[*?\[\]\r\n]|Sysmon' -or @($channel.queryIds).Count -eq 0) { throw 'Invalid native WEF query inventory.' }
        }
    }
    return $profile
}

function Get-WelaDescriptorBytes {
    param($Descriptor)
    $bytes = New-Object byte[] $Descriptor.BinaryLength
    $Descriptor.GetBinaryForm($bytes, 0)
    return ,$bytes
}

function Test-WelaChannelDescriptorEqual {
    param([string]$First, [string]$Second)
    if (-not $First -or -not $Second) { return $false }
    try {
        $a = [System.Security.AccessControl.RawSecurityDescriptor]::new($First)
        $b = [System.Security.AccessControl.RawSecurityDescriptor]::new($Second)
        return [Convert]::ToBase64String((Get-WelaDescriptorBytes $a)) -ceq [Convert]::ToBase64String((Get-WelaDescriptorBytes $b))
    } catch { return $false }
}

function Get-WelaChannelAccessPlan {
    param([string]$SecurityDescriptor)
    $result = [ordered]@{
        State = 'Unknown'; Sid = 'S-1-5-32-573'; AccessMask = 1
        ProposedDescriptor = $null; ExistingAceCount = $null; AddedAceIndex = $null
        EffectiveReadAccess = 'Not tested'; Diagnostic = ''
    }
    try {
        if (-not $SecurityDescriptor) { throw 'Channel security descriptor was not readable.' }
        $original = [System.Security.AccessControl.RawSecurityDescriptor]::new($SecurityDescriptor)
        if (-not ($original.ControlFlags -band [System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -or $null -eq $original.DiscretionaryAcl) {
            throw 'Absent/null DACL requires manual review; adding a DACL would change unrelated access.'
        }
        $result.ExistingAceCount = $original.DiscretionaryAcl.Count
        $grant = $false; $deny = $false; $unknownAce = $false
        foreach ($ace in $original.DiscretionaryAcl) {
            if ($ace -isnot [System.Security.AccessControl.KnownAce]) { $unknownAce = $true; continue }
            if ($ace.AceFlags -band [System.Security.AccessControl.AceFlags]::InheritOnly) { continue }
            $readMask = ($ace.AccessMask -band 1) -or ($ace.AccessMask -band 268435456) -or ($ace.AccessMask -band [int]::MinValue)
            if ($readMask -and $ace.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessDenied) { $deny = $true }
            if ($ace -is [System.Security.AccessControl.CommonAce] -and -not $ace.IsCallback -and
                $ace.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessAllowed -and
                $ace.SecurityIdentifier.Value -eq $result.Sid -and ($ace.AccessMask -band 1)) { $grant = $true }
        }
        if ($unknownAce) { throw 'An unknown ACE requires manual review; the descriptor is preserved without mutation.' }
        if ($deny) { throw 'A read-deny ACE may affect the forwarding token; the descriptor is preserved for manual review.' }
        if ($grant) { $result.State = 'GrantPresent'; return [pscustomobject]$result }
        $copy = [System.Security.AccessControl.RawSecurityDescriptor]::new((Get-WelaDescriptorBytes $original), 0)
        $newAce = [System.Security.AccessControl.CommonAce]::new(
            [System.Security.AccessControl.AceFlags]::None,
            [System.Security.AccessControl.AceQualifier]::AccessAllowed, 1,
            [System.Security.Principal.SecurityIdentifier]::new($result.Sid), $false, $null)
        # Retain every existing ACE, including callback/object ACEs, in original order.
        # Place the explicit allow before inherited entries; do not canonicalize others.
        $index = $copy.DiscretionaryAcl.Count
        for ($i = 0; $i -lt $copy.DiscretionaryAcl.Count; $i++) {
            if ($copy.DiscretionaryAcl[$i].AceFlags -band [System.Security.AccessControl.AceFlags]::Inherited) { $index = $i; break }
        }
        $copy.DiscretionaryAcl.InsertAce($index, $newAce)
        $sddl = $copy.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)
        $roundTrip = [System.Security.AccessControl.RawSecurityDescriptor]::new($sddl)
        if ([Convert]::ToBase64String((Get-WelaDescriptorBytes $copy)) -cne [Convert]::ToBase64String((Get-WelaDescriptorBytes $roundTrip))) {
            throw 'SDDL conversion was not lossless; refusing to replace the channel descriptor.'
        }
        $result.State = 'GrantRequired'; $result.ProposedDescriptor = $sddl; $result.AddedAceIndex = $index
    } catch {
        $result.State = 'ManualReview'; $result.Diagnostic = $_.Exception.Message
    }
    [pscustomobject]$result
}

function Get-WelaNativeChannelInventory {
    param($Profile, [ValidateSet('Baseline', 'Suspect', 'Both')][string]$QuerySet = 'Both')
    $selected = if ($QuerySet -eq 'Both') { @('Baseline', 'Suspect') } else { @($QuerySet) }
    $entries = @{}
    foreach ($set in $selected) {
        foreach ($channel in $Profile.querySets.$set.channels) {
            if (-not $entries.ContainsKey($channel.name)) { $entries[$channel.name] = @() }
            $entries[$channel.name] += [pscustomobject]@{ QuerySet = $set; QueryIds = @($channel.queryIds) }
        }
    }
    foreach ($name in @($entries.Keys | Sort-Object)) {
        $channel = Get-WelaNativeChannel -Name $name
        $unmet = @()
        if ($channel.State -eq 'Not installed') { $unmet += 'Channel not installed; review role/query applicability.' }
        elseif ($channel.State -ne 'Enabled') { $unmet += "Channel enabled state is $($channel.State)." }
        if (-not $channel.SecurityDescriptor) { $unmet += 'Channel security descriptor unreadable.' }
        # A channel ACE does not establish group membership, token access, producer
        # configuration or WEF ingestion. No usable-rule credit is derived here.
        $unmet += @('Event producer/audit policy and representative event generation not verified.',
            'Intended forwarding identity token and actual event read not tested.',
            'WEF subscription/transport and collector ingestion not verified.')
        [pscustomobject]@{
            Channel = $channel; Queries = @($entries[$name]); Prerequisites = $unmet
            EffectiveReadAccess = 'Not tested'; EventGeneration = 'Not tested'; Forwarding = 'Not tested'
        }
    }
}

Export-ModuleMember -Function Get-WelaNativeChannelProfile, Test-WelaChannelDescriptorEqual, Get-WelaChannelAccessPlan, Get-WelaNativeChannelInventory
