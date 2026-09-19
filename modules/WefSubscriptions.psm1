# Bounded native, domain source-initiated WEF input model. No Windows mutations.
function Read-WelaWefXml {
    param([string]$Xml)
    $settings = New-Object Xml.XmlReaderSettings
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit; $settings.XmlResolver = $null; $settings.MaxCharactersInDocument = 10485760
    $reader = [Xml.XmlReader]::Create((New-Object IO.StringReader($Xml)), $settings)
    try { $doc = New-Object Xml.XmlDocument; $doc.XmlResolver = $null; $doc.Load($reader); return ,$doc }
    finally { $reader.Dispose() }
}

function Test-WelaWefContainerText {
    param($Node)
    foreach ($child in $Node.ChildNodes) {
        if ($child.NodeType -eq 'ProcessingInstruction' -or ($child.NodeType -in @('Text','CDATA') -and -not [string]::IsNullOrWhiteSpace($child.Value))) { throw 'Unexpected text or processing instruction in XML container.' }
    }
}

function Get-WelaWefXmlKey {
    param($Node)
    $attributes = @($Node.Attributes | Where-Object { $_.Name -ne 'xmlns' } | Sort-Object Name | ForEach-Object { @($_.Name, $_.Value) -join '=' })
    $children = @($Node.ChildNodes | Where-Object NodeType -eq Element | ForEach-Object { Get-WelaWefXmlKey $_ })
    # Text/CDATA boundaries have no XML semantic meaning. Trimming individual
    # fragments would erase significant whitespace inside XPath string literals.
    $text = (@($Node.ChildNodes | Where-Object { $_.NodeType -in @('Text','CDATA') } | ForEach-Object { $_.Value }) -join '').Trim()
    ConvertTo-Json -InputObject @($Node.LocalName, $Node.NamespaceURI, $attributes, $text, $children) -Depth 30 -Compress
}

function ConvertFrom-WelaWefQuery {
    param([string]$Xml)
    $doc = Read-WelaWefXml $Xml
    if ($doc.DocumentElement.Name -cne 'QueryList' -or $doc.DocumentElement.NamespaceURI -or $doc.DocumentElement.Attributes.Count) { throw 'Query must contain an unqualified QueryList without attributes.' }
    Test-WelaWefContainerText $doc
    Test-WelaWefContainerText $doc.DocumentElement
    if ($Xml -match '(?i)Sysmon|\bEMET\b') { throw 'Sysmon and EMET subscriptions are outside native-only scope.' }
    $rows = @(); $ids = @{}
    foreach ($query in @($doc.DocumentElement.ChildNodes | Where-Object NodeType -eq Element)) {
        if ($query.Name -cne 'Query' -or $query.NamespaceURI -or @($query.Attributes | Where-Object Name -cnotin @('Id','Path')).Count) { throw 'Unsupported Query element/attribute.' }
        $id = $query.GetAttribute('Id')
        Test-WelaWefContainerText $query
        if ($id -notmatch '^\d+$' -or $ids.ContainsKey($id)) { throw 'Query IDs must be explicit and unique integers.' }
        $ids[$id] = $true
        $selectCount = 0
        foreach ($filter in @($query.ChildNodes | Where-Object NodeType -eq Element)) {
            if ($filter.Name -cnotin @('Select','Suppress') -or $filter.NamespaceURI -or @($filter.Attributes | Where-Object Name -cne 'Path').Count -or @($filter.ChildNodes | Where-Object NodeType -eq Element).Count) { throw 'Unsupported query filter structure.' }
            $channel = $filter.GetAttribute('Path'); if (-not $channel) { $channel = $query.GetAttribute('Path') }
            if ($channel -match '(?i)Sysmon|\bEMET\b') { throw 'Decoded Sysmon/EMET channel names are outside native-only scope.' }
            if (@($filter.ChildNodes | Where-Object NodeType -eq ProcessingInstruction).Count) { throw 'Processing instructions in XPath filters are unsupported.' }
            if ($channel -notin @('Security','System','Application','Windows PowerShell') -and $channel -notmatch '^Microsoft-Windows-[A-Za-z0-9 -]+/[A-Za-z0-9 -]+$') { throw "Unsupported/non-native or wildcard channel: $channel" }
            if ([string]::IsNullOrWhiteSpace($filter.InnerText)) { throw 'Empty XPath filter is not accepted.' }
            if ($filter.Name -eq 'Select') { $selectCount++ }
            $rows += [pscustomobject]@{ QueryId=$id; Channel=$channel; Operation=$filter.Name; XPath=$filter.InnerText.Trim() }
        }
        if (-not $selectCount) { throw 'Each query must contain at least one Select.' }
    }
    if (-not $rows.Count) { throw 'Empty QueryList is not accepted.' }
    [pscustomobject]@{ Xml=$doc.OuterXml; Key=(Get-WelaWefXmlKey $doc.DocumentElement); Filters=$rows; Channels=@($rows.Channel | Sort-Object -Unique) }
}

function Get-WelaWefAuthorization {
    param([string[]]$SourceSids)
    if (-not $SourceSids.Count) { throw 'Explicit source computer/group domain SIDs are required; no default broad authorization is used.' }
    foreach ($sid in $SourceSids) { if ($sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { throw "Expected an explicit domain computer/group SID: $sid" } }
    return 'O:NSG:NSD:' + ((@($SourceSids | Sort-Object -Unique) | ForEach-Object { '(A;;GA;;;' + $_ + ')' }) -join '')
}

function ConvertFrom-WelaWefSubscription {
    param([string]$Xml, [string[]]$SourceSids, [switch]$Observed)
    $doc = Read-WelaWefXml $Xml
    $ns = 'http://schemas.microsoft.com/2006/03/windows/events/subscription'
    if ($doc.DocumentElement.LocalName -cne 'Subscription' -or $doc.DocumentElement.NamespaceURI -cne $ns) { throw 'Expected the native Windows Subscription XML namespace.' }
    Test-WelaWefContainerText $doc
    Test-WelaWefContainerText $doc.DocumentElement
    if (@($doc.DocumentElement.Attributes | Where-Object Name -cne 'xmlns').Count) { throw 'Unknown subscription root attributes.' }
    $allowed = @('SubscriptionId','SubscriptionType','Description','Enabled','Uri','ConfigurationMode','Query','ReadExistingEvents','TransportName','ContentFormat','Locale','LogFile','PublisherName','AllowedSourceDomainComputers','AllowedSourceNonDomainComputers')
    if ($Observed) { $allowed += @('Delivery','EventSources','CredentialsType','TransportPort') }
    $elements = @{}
    foreach ($node in @($doc.DocumentElement.ChildNodes | Where-Object NodeType -eq Element)) {
        if ($node.NamespaceURI -cne $ns -or $node.LocalName -cnotin $allowed -or $elements.ContainsKey($node.LocalName)) { throw "Unknown/duplicate subscription field: $($node.Name)" }
        $elements[$node.LocalName] = $node
    }
    foreach ($required in @('SubscriptionId','SubscriptionType','Enabled','Uri','ConfigurationMode','Query','ReadExistingEvents','TransportName','ContentFormat','Locale','LogFile','AllowedSourceDomainComputers')) {
        if (-not $elements.ContainsKey($required)) { throw "Subscription requires explicit $required." }
    }
    $id = $elements.SubscriptionId.InnerText
    if ($id -notmatch '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}$') { throw 'Unsupported subscription ID.' }
    if ($elements.SubscriptionType.InnerText -cne 'SourceInitiated' -or $elements.TransportName.InnerText -ine 'HTTP' -or
        $elements.Uri.InnerText -cne 'http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog' -or $elements.LogFile.InnerText -cne 'ForwardedEvents') { throw 'Only HTTP source-initiated native EventLog subscriptions to ForwardedEvents are supported.' }
    if ($elements.ConfigurationMode.InnerText -cnotin @('Normal','MinLatency','MinBandwidth')) { throw 'Use a native Normal, MinLatency or MinBandwidth preset; Custom delivery is outside this initial scope.' }
    foreach ($field in @('Enabled','ReadExistingEvents')) { if ($elements[$field].InnerText -cnotin @('true','false')) { throw "$field must be explicit true or false." } }
    if ($elements.ContentFormat.InnerText -cnotin @('Events','RenderedText')) { throw 'Unsupported content format.' }
    if ($elements.Locale.GetAttribute('Language') -notmatch '^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$') { throw 'Explicit locale language is required.' }
    if ($elements.PublisherName -and $elements.PublisherName.InnerText -cne 'Microsoft-Windows-EventCollector') { throw 'Only the native EventCollector publisher is supported.' }
    if ($elements.AllowedSourceNonDomainComputers) {
        $nonDomain = $elements.AllowedSourceNonDomainComputers
        if ($nonDomain.Attributes.Count -or -not [string]::IsNullOrWhiteSpace($nonDomain.InnerText)) { throw 'Non-domain/certificate sources require a separately designed topology.' }
        foreach ($child in @($nonDomain.ChildNodes | Where-Object NodeType -eq Element)) {
            if ($child.LocalName -cne 'AllowedIssuerCAList' -or $child.NamespaceURI -cne $ns -or $child.Attributes.Count -or $child.ChildNodes.Count) { throw 'Unknown non-domain authorization structure is not accepted.' }
        }
    }
    if ($elements.CredentialsType -and $elements.CredentialsType.InnerText -cne 'Default') { throw 'Explicit credentials are not accepted.' }
    if ($elements.TransportPort -and $elements.TransportPort.InnerText -ne '5985') { throw 'Only the standard HTTP transport port is supported.' }
    foreach ($node in $elements.Values) {
        if ($node.LocalName -in @('AllowedSourceNonDomainComputers','Delivery','EventSources')) { continue }
        if (@($node.ChildNodes | Where-Object NodeType -eq ProcessingInstruction).Count) { throw 'Processing instructions in subscription settings are unsupported.' }
        if (@($node.ChildNodes | Where-Object NodeType -eq Element).Count -or @($node.Attributes | Where-Object { -not ($node.LocalName -eq 'Locale' -and $_.Name -ceq 'Language') }).Count) { throw "Unexpected nested/attributed subscription setting: $($node.Name)" }
    }
    $authorization = Get-WelaWefAuthorization $SourceSids
    $currentAuthorization = $elements.AllowedSourceDomainComputers.InnerText.Trim()
    if ($currentAuthorization -and $currentAuthorization -cne $authorization) { throw 'Subscription source authorization does not exactly match the explicitly configured source SIDs.' }
    if ($Observed -and -not $currentAuthorization) { throw 'Observed subscription has missing/default source authorization.' }
    $elements.AllowedSourceDomainComputers.InnerText = $authorization
    $query = ConvertFrom-WelaWefQuery $elements.Query.InnerText
    $definition = [ordered]@{
        Id=$id; Enabled=($elements.Enabled.InnerText -eq 'true'); ConfigurationMode=$elements.ConfigurationMode.InnerText
        ReadExistingEvents=($elements.ReadExistingEvents.InnerText -eq 'true'); ContentFormat=$elements.ContentFormat.InnerText
        Locale=$elements.Locale.GetAttribute('Language'); Description=$(if ($elements.Description) { $elements.Description.InnerText } else { '' })
        LogFile='ForwardedEvents'; SourceAuthorization=$authorization; QueryKey=$query.Key
    }
    [pscustomobject]@{ Id=$id; Xml=$doc.OuterXml; Definition=[pscustomobject]$definition; Key=($definition | ConvertTo-Json -Depth 30 -Compress); Query=$query; SourceSids=@($SourceSids | Sort-Object -Unique) }
}

function Import-WelaWefConfig {
    param([string]$Path, [ValidateSet('Source','Collector')][string]$Role)
    $full = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $config = Get-Content -LiteralPath $full -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $known = @('SchemaVersion','Role','CollectorFqdn','CollectorUri','Authentication','SourceSids','SubscriptionFiles','Hardening','SubscriptionManagerSlot','RefreshSeconds','GrantNetworkServiceRead','ApplyChannelProfile','GrantCapi2Read','ListenerAddress','IngressRuleName','IngressLocalAddresses','IngressRemoteAddresses')
    foreach ($property in $config.PSObject.Properties) { if ($property.Name -cnotin $known) { throw "Unknown WEF config field: $($property.Name)" } }
    if ($config.SchemaVersion -ne 1 -or $config.Role -cne $Role) { throw "Expected schema 1 $Role configuration." }
    if ($config.CollectorFqdn -notmatch '^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$') { throw 'An actual collector FQDN is required.' }
    $ipLiteral=$null
    if ([Net.IPAddress]::TryParse([string]$config.CollectorFqdn,[ref]$ipLiteral)) { throw 'CollectorFqdn must be a DNS identity, not an IP literal.' }
    $uri = $null
    if (-not [Uri]::TryCreate([string]$config.CollectorUri,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -ne 'http' -or $uri.Port -ne 5985 -or $uri.DnsSafeHost -ine $config.CollectorFqdn -or
        $uri.AbsolutePath -cne '/wsman/SubscriptionManager/WEC' -or $uri.Query -or $uri.Fragment -or $uri.UserInfo) { throw 'CollectorUri must match CollectorFqdn and http://FQDN:5985/wsman/SubscriptionManager/WEC exactly, without credentials/query/fragment.' }
    if ($config.Authentication -cne 'Kerberos' -or $config.Hardening -cnotin @('AssessOnly','ApplyASD')) { throw 'Explicit Kerberos authentication and AssessOnly/ApplyASD hardening selection are required.' }
    $null = Get-WelaWefAuthorization @($config.SourceSids)
    if (@($config.SubscriptionFiles).Count -lt 1 -or @($config.SubscriptionFiles).Count -gt 32) { throw 'Select 1 to 32 explicit native subscription XML files.' }
    if ($Role -eq 'Source') {
        foreach ($field in @('ListenerAddress','IngressRuleName','IngressLocalAddresses','IngressRemoteAddresses')) { if ($config.PSObject.Properties[$field]) { throw "Collector-only field is not accepted in Source config: $field" } }
        if ([string]$config.SubscriptionManagerSlot -notmatch '^[1-9]\d{0,3}$' -or ($config.RefreshSeconds -isnot [int] -and $config.RefreshSeconds -isnot [long]) -or $config.RefreshSeconds -lt 10 -or $config.RefreshSeconds -gt 86400) { throw 'Source config requires a numeric SubscriptionManagerSlot (1..9999) and integer RefreshSeconds (10..86400).' }
        foreach ($field in @('GrantNetworkServiceRead','ApplyChannelProfile','GrantCapi2Read')) { if ($config.$field -isnot [bool]) { throw "Explicit boolean $field is required." } }
        if ($config.GrantCapi2Read -and -not $config.ApplyChannelProfile) { throw 'GrantCapi2Read requires explicit ApplyChannelProfile.' }
    } else {
        foreach ($field in @('SubscriptionManagerSlot','RefreshSeconds','GrantNetworkServiceRead','ApplyChannelProfile','GrantCapi2Read')) { if ($config.PSObject.Properties[$field]) { throw "Source-only field is not accepted in Collector config: $field" } }
        if (-not $config.ListenerAddress -or -not $config.IngressRuleName -or @($config.IngressLocalAddresses).Count -eq 0 -or @($config.IngressRemoteAddresses).Count -eq 0) { throw 'Collector requires an existing listener address, firewall rule name and explicit local/remote address scopes.' }
        foreach ($range in @($config.IngressLocalAddresses) + @($config.IngressRemoteAddresses)) {
            $parts = [string]$range -split '/'; $address = $null
            if ($parts.Count -gt 2 -or -not [Net.IPAddress]::TryParse($parts[0],[ref]$address) -or ($parts.Count -eq 2 -and ($parts[1] -notmatch '^\d+$' -or [int]$parts[1] -lt 1 -or [int]$parts[1] -gt $(if ($address.AddressFamily -eq 'InterNetwork') { 32 } else { 128 })))) { throw "Use explicit IP/CIDR ingress addresses, not Any or zero-prefix ranges: $range" }
        }
    }
    $subscriptions = @(); $ids = @{}
    foreach ($file in $config.SubscriptionFiles) {
        $target = if ([IO.Path]::IsPathRooted($file)) { $file } else { Join-Path (Split-Path $full -Parent) $file }
        $xml = Get-Content -LiteralPath $target -Raw -Encoding UTF8 -ErrorAction Stop
        $subscription = ConvertFrom-WelaWefSubscription -Xml $xml -SourceSids @($config.SourceSids)
        if ($ids.ContainsKey($subscription.Id)) { throw 'Duplicate subscription ID in selected files.' }
        $ids[$subscription.Id] = $true; $subscriptions += $subscription
    }
    [pscustomobject]@{ Config=$config; Path=$full; Subscriptions=$subscriptions }
}

function Read-WelaWecSubscriptionXml {
    param([Parameter(Mandatory)][string]$Id)
    if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess){throw 'Native WEC XML reads require 64-bit Windows.'}
    $path=Join-Path $PSScriptRoot 'WecSubscriptionXml.cs';$hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
    if(-not ('Wela.WecXml.Reader' -as [type])){Add-Type -Path $path -ErrorAction Stop;$script:WelaWecXmlSourceHash=$hash}
    if($script:WelaWecXmlSourceHash -cne $hash){throw 'Loaded native WEC XML reader differs from its source; start a fresh session.'}
    [Wela.WecXml.Reader]::ReadXml($Id)
}

Export-ModuleMember -Function Read-WelaWecSubscriptionXml, Read-WelaWefXml, Get-WelaWefXmlKey, ConvertFrom-WelaWefQuery, Get-WelaWefAuthorization, ConvertFrom-WelaWefSubscription, Import-WelaWefConfig
