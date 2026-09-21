# Read-only local NetSecurity evidence. No policy, service or traffic changes.
function Test-WelaIpsecConditionalPolicy {
    param($Plan, $Policy)
    return (-not $Plan.PSObject.Properties['CustomProfileSource'] -and
        $Plan.profile -ceq 'microsoft-stronger-reviewed-2026-09' -and
        $Policy.guid -ieq '0CCE9218-69AE-11D9-BED3-505054503030' -and $Policy.mode -eq 'optional')
}

function Get-WelaIpsecPrerequisite {
    [CmdletBinding()]
    param([switch]$Offline,
        [scriptblock]$ReadRules = { NetSecurity\Get-NetIPsecRule -PolicyStore ActiveStore -ErrorAction Stop },
        [scriptblock]$ReadAssociations = { NetSecurity\Get-NetIPsecMainModeSA -ErrorAction Stop })
    $started = [DateTime]::UtcNow.ToString('o')
    $rules = @(); $associations = @(); $reads = @(); $diagnostics = @()
    if ($Offline) { $diagnostics += 'Offline scenario; this host was not queried.' }
    else {
        foreach ($source in @('ActiveStoreRules', 'MainModeAssociations')) {
            $status = 'Complete'; $errorText = ''; $items = @()
            try {
                $reader = if ($source -eq 'ActiveStoreRules') { $ReadRules } else { $ReadAssociations }
                # Keep at most 4096 observations per native source. A cap is not an empty/successful inventory.
                $items = @(& $reader | Select-Object -First 4097)
                if ($items.Count -gt 4096) { throw 'Observation cap exceeded (4096 records).' }
                $seen = @{}
                foreach ($item in $items) {
                    if ($source -eq 'ActiveStoreRules') {
                        foreach ($property in @('Name', 'Enabled', 'InboundSecurity', 'OutboundSecurity', 'PrimaryStatus')) {
                            if ($null -eq $item -or -not $item.PSObject.Properties[$property] -or $null -eq $item.$property) { throw "Missing native rule property: $property." }
                        }
                        $name = [string]$item.Name
                        $enabled = [string]$item.Enabled; $inbound = [string]$item.InboundSecurity; $outbound = [string]$item.OutboundSecurity; $health = [string]$item.PrimaryStatus
                        if (-not $name -or $name.Length -gt 1024 -or $seen.ContainsKey($name) -or $enabled -cnotin @('True','False') -or
                            $inbound -cnotin @('None','Request','Require') -or $outbound -cnotin @('None','Request','Require') -or
                            $health -cnotin @('OK','Degraded','Error','Unknown')) { throw 'Unrecognized or duplicate native IPsec rule observation.' }
                        $seen[$name] = $true
                        $qualifies = $enabled -ceq 'True' -and ($inbound -cne 'None' -or $outbound -cne 'None') -and $health -ceq 'OK'
                        $rules += [pscustomobject]@{ Name=$name; Enabled=$enabled; InboundSecurity=$inbound; OutboundSecurity=$outbound; PrimaryStatus=$health; Qualifies=$qualifies }
                        if ($enabled -ceq 'True' -and ($inbound -cne 'None' -or $outbound -cne 'None') -and $health -cne 'OK') { throw 'Enabled non-exemption rule has uncertain effective health.' }
                    } else {
                        foreach ($property in @('Name','LocalEndpoint','RemoteEndpoint')) {
                            if ($null -eq $item -or -not $item.PSObject.Properties[$property] -or -not [string]$item.$property) { throw "Missing native association property: $property." }
                        }
                        $name = [string]$item.Name; $local = [string]$item.LocalEndpoint; $remote = [string]$item.RemoteEndpoint
                        $address = $null
                        if ($name.Length -gt 1024 -or $seen.ContainsKey($name) -or -not [Net.IPAddress]::TryParse($local,[ref]$address) -or -not [Net.IPAddress]::TryParse($remote,[ref]$address)) { throw 'Unrecognized or duplicate main-mode association.' }
                        $seen[$name] = $true
                        $associations += [pscustomobject]@{ Name=$name; LocalEndpoint=$local; RemoteEndpoint=$remote }
                    }
                }
            } catch { $status = 'Unknown'; $errorText = $_.Exception.Message; $diagnostics += "$source`: $errorText" }
            $reads += [pscustomobject]@{ Source=$source; Status=$status; ObservedCount=$items.Count; Diagnostic=$errorText }
        }
    }
    $status = if ($Offline -or @($reads | Where-Object Status -ne Complete).Count) { 'Unknown' }
        elseif (@($rules | Where-Object Qualifies).Count -or $associations.Count) { 'Applicable' }
        else { 'NotObservedWithinScope' }
    [pscustomobject][ordered]@{
        SchemaVersion=1; Status=$status; Scope='Local NetSecurity ActiveStore rules and current main-mode SAs'
        StartedUtc=$started; CompletedUtc=[DateTime]::UtcNow.ToString('o'); ComputerName=$env:COMPUTERNAME
        Basis=$(if ($status -eq 'Applicable') { 'Enabled healthy non-exemption effective rule or current main-mode SA observed.' } else { 'No complete positive prerequisite evidence.' })
        Reads=$reads; Rules=$rules; MainModeAssociations=$associations; Diagnostic=($diagnostics -join ' ')
        Limitations='Point-in-time local scope. Configured rules do not prove matching traffic, successful negotiation or audit events. Absence does not exclude legacy IPsec, VPN or other providers. No event-volume, failure-outcome or Sigma credit.'
    }
}

function Assert-WelaIpsecPrerequisite {
    param($Evidence)
    if ($null -eq $Evidence -or $Evidence.Status -cne 'Applicable') {
        $status = if ($Evidence) { $Evidence.Status } else { 'Unknown' }
        throw "IPsec Main Mode prerequisite is $status; this conditional audit setting was not changed. $($Evidence.Diagnostic)"
    }
}
