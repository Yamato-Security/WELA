# Safe fixtures exercise the public command, native argument boundary and JSON report.
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/WefSubscriptions.psm1') -Force
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/WefDeployment.ps1')
$script:ScriptRoot=$repo; $script:count=0
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-wef-' + [guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory $temp
Copy-Item (Join-Path $repo 'config/wef-examples/*') $temp
function Assert($Value,[string]$Message) { if (-not $Value) { throw "FAIL: $Message" }; $script:count++ }
function Assert-Throws([scriptblock]$Code,[string]$Message) { $caught=$false; try { & $Code | Out-Null } catch { $caught=$true }; Assert $caught $Message }
function Reset-Fixture {
    $global:WelaWefFixture=@{
        Services=@{ WinRM=[pscustomobject]@{ StartMode='Auto'; State='Running' }; Wecsvc=[pscustomobject]@{ StartMode='Auto'; State='Running' } }
        Wsman=@{ 'WSMan:\localhost\Client\Auth\Digest'='false'; 'WSMan:\localhost\Client\Auth\Kerberos'='true'; 'WSMan:\localhost\Service\Auth\CbtHardeningLevel'='strict'; 'WSMan:\localhost\Shell\AllowRemoteShellAccess'='false'; 'WSMan:\localhost\Service\Auth\Kerberos'='true' }
        Policy=@{}; MemberSids=@('S-1-5-20','S-1-5-21-11-22-33-1000'); Slots=@{}; Subs=@{}; Writes=(New-Object 'System.Collections.Generic.List[object]')
        Listener=$true; Ingress=$true; Domain=$true; Fqdn='collector.example.test'; Mode=3; Fail=''; Reads=@{}; DriftKind=''; DriftAt=0; Deny=''; Admx=$true
        Forwarded=$true; ChannelEnabled=$true; Prompt='Y'
    }
    $script:backup=Join-Path $temp ([guid]::NewGuid().ToString('N')); $global:WelaWefFixture.Backup=$script:backup
    $script:source=Get-Content (Join-Path $repo 'config/wef-examples/source.json') -Raw | ConvertFrom-Json
    $script:collector=Get-Content (Join-Path $repo 'config/wef-examples/collector.json') -Raw | ConvertFrom-Json
    Save-Configs
}
function Save-Configs {
    $script:source | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $temp 'source.json')
    $script:collector | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $temp 'collector.json')
}
function Count-Read([string]$Kind) {
    $f=$global:WelaWefFixture
    if (-not $f.Reads.ContainsKey($Kind)) { $f.Reads[$Kind]=0 }; $f.Reads[$Kind]++
    if ($f.Deny -eq $Kind) { throw 'Fixture access denied' }
    if ($f.DriftKind -eq $Kind -and $f.Reads[$Kind] -eq $f.DriftAt) {
        switch ($Kind) {
            'SubscriptionManager' { $f.Slots['1']=[pscustomobject]@{ KeyExists=$true; ValueExists=$true; Value='concurrent'; Type='String' } }
            'Readers' { $f.MemberSids=@('S-1-5-21-11-22-33-9999') }
            'Wsman' { $f.Policy['WSMan:\localhost\Client\Auth\Digest']='GPO' }
        }
    }
}
function Record-Write([string]$Kind,$Value) {
    $f=$global:WelaWefFixture
    $journal=Join-Path $f.Backup 'before.jsonl'
    Assert (Test-Path $journal) 'Recovery journal exists before each setter/native write'
    $record=@(Get-Content $journal | ForEach-Object { $_ | ConvertFrom-Json })[-1]
    Assert ($null -ne $record.Before) 'Journal contains pre-change state'
    $f.Writes.Add([pscustomobject]@{ Kind=$Kind; Value=$Value })
    if ($f.Fail -eq $Kind) { throw 'Fixture native/setter failure' }
}
function Get-WelaWefHost { $f=$global:WelaWefFixture; [pscustomobject]@{ DomainJoined=$f.Domain; Fqdn=$f.Fqdn; DomainRole=$f.Mode } }
function Test-WelaWefAdmx { if (-not $global:WelaWefFixture.Admx) { throw 'Unsupported fixture ADMX' }; return $true }
function Get-CimInstance { param($ClassName,$Filter) if ($ClassName -ne 'Win32_Service') { throw 'Unexpected CIM class' }; $name=($Filter -split "'")[1]; $global:WelaWefFixture.Services[$name].PSObject.Copy() }
function Set-Service { param($Name,$StartupType) Record-Write Service $Name; $global:WelaWefFixture.Services[$Name].StartMode='Auto' }
function Start-Service { param($Name) Record-Write Service $Name; $global:WelaWefFixture.Services[$Name].State='Running' }
function Get-Item {
    param($LiteralPath)
    Count-Read Wsman
    if (-not $global:WelaWefFixture.Wsman.ContainsKey($LiteralPath)) { throw 'Unexpected WSMan path' }
    [pscustomobject]@{ Value=$global:WelaWefFixture.Wsman[$LiteralPath]; SourceOfValue=[string]$global:WelaWefFixture.Policy[$LiteralPath] }
}
function Set-Item { param($LiteralPath,$Value) Record-Write Wsman $LiteralPath; if ($global:WelaWefFixture.Fail -ne 'false-success') { $global:WelaWefFixture.Wsman[$LiteralPath]=[string]$Value } }
function Get-LocalGroup { param($SID) Assert ($SID -eq 'S-1-5-32-573') 'Only builtin Event Log Readers is selected by SID'; [pscustomobject]@{ SID=$SID } }
function Get-LocalGroupMember { param($Group) Count-Read Readers; foreach ($sid in $global:WelaWefFixture.MemberSids) { [pscustomobject]@{ SID=$sid } } }
function Add-LocalGroupMember { param($Group,$Member) Assert ($Member -eq 'S-1-5-20') 'Only NETWORK SERVICE membership is added'; Record-Write Readers $Member; $global:WelaWefFixture.MemberSids+=@($Member) }
function Get-WelaRegistryState { param($Path,$Name) Count-Read SubscriptionManager; if ($global:WelaWefFixture.Slots.ContainsKey($Name)) { return $global:WelaWefFixture.Slots[$Name].PSObject.Copy() }; [pscustomobject]@{ KeyExists=$true; ValueExists=$false; Value=$null; Type=$null } }
function New-WelaRegistryKey { param($Path) }
function New-ItemProperty { param($LiteralPath,$Name,$Value,$PropertyType) Record-Write SubscriptionManager $Name; Assert ($PropertyType -eq 'String') 'SubscriptionManager uses REG_SZ'; $global:WelaWefFixture.Slots[$Name]=[pscustomobject]@{ KeyExists=$true; ValueExists=$true; Value=$Value; Type=$PropertyType } }
function Get-WelaNativeChannel {
    param($Name)
    $enabled=if ($Name -eq 'ForwardedEvents') { $global:WelaWefFixture.Forwarded } else { $global:WelaWefFixture.ChannelEnabled }
    [pscustomobject]@{ Name=$Name; State=$(if ($enabled) { 'Enabled' } else { 'Disabled' }); IsEnabled=$enabled; MaximumSizeInBytes=[long]123207680; LogMode='Retain'; SecurityDescriptor='O:BAG:SYD:(A;;0x1;;;SY)'; Error=$null; MetadataErrors=@{} }
}
function Test-WelaNativeChannelSnapshot { param($Snapshot) return $Snapshot.IsEnabled -is [bool] -and $Snapshot.SecurityDescriptor }
function Get-WSManInstance {
    param($ResourceURI,[switch]$Enumerate)
    if ($global:WelaWefFixture.Listener) { [pscustomobject]@{ Address='*'; Transport='HTTP'; Port=5985; Enabled=$true; URLPrefix='wsman'; ListeningOn=@('192.0.2.10') } }
}
function Get-NetFirewallRule { param($Name,$PolicyStore) Assert ($PolicyStore -eq 'ActiveStore') 'Ingress is read from effective ActiveStore'; [pscustomobject]@{ Name=$Name; Enabled=$global:WelaWefFixture.Ingress; Direction='Inbound'; Action='Allow'; Profile='Domain'; PolicyStoreSourceType='Local'; EnforcementStatus='Full' } }
function Get-NetFirewallPortFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline)]$Rule) process { [pscustomobject]@{ Protocol='TCP'; LocalPort='5985'; RemotePort='Any' } } }
function Get-NetFirewallAddressFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline)]$Rule) process { [pscustomobject]@{ LocalAddress=@('192.0.2.10/255.255.255.255'); RemoteAddress=@('192.0.2.0/255.255.255.0') } } }
function Read-Host { param($Prompt) return $global:WelaWefFixture.Prompt }
function Get-WelaWecSubscriptionIds {
    if($global:WelaWefFixture.Fail -eq 'Inventory'){throw 'Incomplete native inventory'}
    @($global:WelaWefFixture.Subs.Keys)
}
function Read-WelaWecSubscriptionXml {
    param($Id)
    if($global:WelaWefFixture.Fail -eq 'ReadXml' -or -not $global:WelaWefFixture.Subs.ContainsKey($Id)){throw 'Native definition is no longer readable'}
    $global:WelaWefFixture.Subs[$Id]
}
function Invoke-WelaNative {
    param($FilePath,$Arguments)
    $f=$global:WelaWefFixture
    if ($FilePath -eq 'wevtutil.exe') {
        Assert (($Arguments -join ' ') -eq 'sl ForwardedEvents /e:true') 'ForwardedEvents enablement leaves size/mode/ACL untouched'
        Record-Write ForwardedEvents $Arguments; $f.Forwarded=$true
        return [pscustomobject]@{ ExitCode=0; Diagnostic=''; Output=@() }
    }
    Assert ($FilePath -eq 'wecutil.exe') 'Only native wecutil subscription API is called'
    switch ($Arguments[0]) {
        {$_ -in @('es','gs')} {throw 'Subscription inventory and XML must bypass console decoding.'}
        'gr' { return [pscustomobject]@{ ExitCode=0; Output=@('Localized runtime fixture'); Diagnostic='Localized runtime fixture' } }
        'cs' {
            Record-Write Subscription $Arguments
            $xml=Get-Content -LiteralPath $Arguments[1] -Raw
            $model=ConvertFrom-WelaWefSubscription $xml @('S-1-5-21-111-222-333-1234') -Observed
            Assert ($model.Definition.SourceAuthorization -notmatch ';;;DC\)') 'Native import contains explicit source SIDs rather than default Domain Computers'
            if ($f.Fail -ne 'false-subscription') { $f.Subs[$model.Id]=$xml }
            return [pscustomobject]@{ ExitCode=0; Output=@(); Diagnostic='Created fixture subscription' }
        }
        default { throw 'Unexpected native operation; no qc, ss or ds is allowed.' }
    }
}
function Invoke-Source([string]$Action='Configure',[switch]$DryRun,[string]$ResultsPath) { Invoke-WelaWefCommand -Role Source -Action $Action -ConfigPath (Join-Path $temp 'source.json') -Auto -DryRun:$DryRun -BackupPath $script:backup -ResultsPath $ResultsPath }
function Invoke-Collector([string]$Action='Configure',[switch]$DryRun,[string]$ResultsPath) { Invoke-WelaWefCommand -Role Collector -Action $Action -ConfigPath (Join-Path $temp 'collector.json') -Auto -DryRun:$DryRun -BackupPath $script:backup -ResultsPath $ResultsPath }
$savedOS=$env:OS
try {
    $env:OS='Windows_NT'
    Reset-Fixture
    $model=Import-WelaWefConfig (Join-Path $temp 'source.json') Source
    Assert ($model.Subscriptions.Count -eq 1 -and $model.Subscriptions[0].Query.Channels[0] -eq 'Security') 'Example native query imports'
    $xml=Get-Content (Join-Path $temp 'native-security.xml') -Raw
    Assert-Throws { ConvertFrom-WelaWefSubscription ($xml -replace 'SourceInitiated','CollectorInitiated') $source.SourceSids } 'Collector-initiated input is rejected'
    Assert-Throws { ConvertFrom-WelaWefSubscription ($xml -replace '>HTTP<','>HTTPS<') $source.SourceSids } 'Unsupported HTTPS topology is rejected'
    Assert-Throws { ConvertFrom-WelaWefSubscription ($xml -replace 'MinLatency','Custom') $source.SourceSids } 'Unreviewed custom delivery is rejected'
    Assert-Throws { ConvertFrom-WelaWefSubscription ($xml -replace 'Path="Security"','Path="Microsoft-Windows-Sysmon/Operational"') $source.SourceSids } 'Sysmon cannot enter native-only subscriptions'
    Assert-Throws { ConvertFrom-WelaWefSubscription ($xml -replace 'Path="Security"','Path="Microsoft-Windows-&#83;ysmon/Operational"') $source.SourceSids } 'Entity-encoded non-native channel names are rejected after decoding'
    Assert-Throws { ConvertFrom-WelaWefSubscription ($xml -replace 'Path="Security"','Path="Vendor-Product/Operational"') $source.SourceSids } 'Unrecognized external-provider channels are rejected'
    Assert-Throws { ConvertFrom-WelaWefSubscription ($xml -replace '<Enabled>true</Enabled>','<Enabled>true</Enabled><Enabled>false</Enabled>') $source.SourceSids } 'Duplicate fields are rejected'
    Assert-Throws { Read-WelaWefXml '<!DOCTYPE x [<!ENTITY x SYSTEM "file:///etc/passwd">]><x>&x;</x>' } 'DTD/entity expansion is rejected'
    Assert-Throws { Get-WelaWefAuthorization @() } 'Empty authorization cannot select native broad defaults'
    Assert-Throws { Get-WelaWefAuthorization @('S-1-1-0') } 'Everyone source authorization is rejected'
    $plain=ConvertFrom-WelaWefQuery '<QueryList><Query Id="0" Path="Security"><Select>*[EventData[Data="foobar"]]</Select></Query></QueryList>'
    $split=ConvertFrom-WelaWefQuery '<QueryList><Query Id="0" Path="Security"><Select>*[EventData[Data="foo<![CDATA[ bar"]]]]></Select></Query></QueryList>'
    Assert ($plain.Key -cne $split.Key -and $plain.Filters[0].XPath -cne $split.Filters[0].XPath) 'Text/CDATA normalization preserves significant XPath literal whitespace'
    $same=ConvertFrom-WelaWefQuery '<QueryList><Query Id="0" Path="Security"><Select>*[EventData[Data="foo<![CDATA[bar"]]]]></Select></Query></QueryList>'
    Assert ($plain.Key -ceq $same.Key) 'Equivalent adjacent text/CDATA serialization has the same key'
    $source.CollectorUri='http://wrong.example.test:5985/wsman/SubscriptionManager/WEC'; Save-Configs
    Assert-Throws { Import-WelaWefConfig (Join-Path $temp 'source.json') Source } 'Mismatched collector identity and URI are rejected'
    $source.CollectorFqdn='10.0.0.1'; $source.CollectorUri='http://10.0.0.1:5985/wsman/SubscriptionManager/WEC'; Save-Configs
    Assert-Throws { Import-WelaWefConfig (Join-Path $temp 'source.json') Source } 'IP literals cannot masquerade as Kerberos FQDN identities'
    Reset-Fixture
    $report=Invoke-Source Plan -ResultsPath (Join-Path $temp 'plan.json')
    $json=Get-Content (Join-Path $temp 'plan.json') -Raw | ConvertFrom-Json
    Assert ($global:WelaWefFixture.Writes.Count -eq 0 -and -not (Test-Path $backup)) 'Plan does not write or create a backup directory'
    Assert ($json.Subscriptions[0].Filters[0].XPath -eq '*[System[(EventID=4740)]]') 'Public JSON preserves exact selected XPath'
    Assert ($json.Subscriptions[0].SourceChannels[0].LogMode -eq 'Retain' -and $json.Subscriptions[0].SourceChannels[0].SecurityDescriptor) 'Public JSON retains channel mode and ACL'
    Assert ($json.Subscriptions[0].EffectiveSourceReadAccess -eq 'Not tested' -and $json.Subscriptions[0].ForwardedSigmaCoverage -eq 'Not assessed') 'Enabled channels/membership do not fabricate effective access or forwarded coverage'
    $report=Invoke-Source Configure -DryRun
    Assert ($global:WelaWefFixture.Writes.Count -eq 0 -and -not (Test-Path $backup)) 'Configure dry-run is mutation and journal free'
    $report=Invoke-Source
    Assert ($report.ExitCode -eq 0 -and $report.LocalConfigurationStatus -eq 'RequestedSettingsMatch') 'Valid source configuration is read back'
    Assert ($global:WelaWefFixture.Slots['1'].Value -eq 'Server=http://collector.example.test:5985/wsman/SubscriptionManager/WEC,Refresh=60') 'Only the selected explicit SubscriptionManager format is written'
    $beforeWrites=$global:WelaWefFixture.Writes.Count; $script:backup=Join-Path $temp ([guid]::NewGuid().ToString('N')); $global:WelaWefFixture.Backup=$backup
    $report=Invoke-Source
    Assert ($report.ExitCode -eq 0 -and $global:WelaWefFixture.Writes.Count -eq $beforeWrites) 'Repeated source configure is idempotent'
    Reset-Fixture
    $global:WelaWefFixture.MemberSids=@('S-1-5-21-11-22-33-1000'); $source.GrantNetworkServiceRead=$true; Save-Configs
    $report=Invoke-Source
    Assert ($report.ExitCode -eq 0 -and $global:WelaWefFixture.MemberSids -contains 'S-1-5-21-11-22-33-1000') 'Explicit group addition preserves existing members'
    Reset-Fixture
    $global:WelaWefFixture.Mode=5; $global:WelaWefFixture.MemberSids=@('S-1-5-21-11-22-33-1000'); $source.GrantNetworkServiceRead=$true; Save-Configs
    $report=Invoke-Source
    Assert ($report.ExitCode -eq 1 -and $global:WelaWefFixture.Writes.Count -eq 0) 'DC BUILTIN membership remains an explicit manual domain-authority prerequisite'
    Reset-Fixture
    $global:WelaWefFixture.Slots['1']=[pscustomobject]@{ KeyExists=$true; ValueExists=$true; Value='operator-existing'; Type='String' }
    $report=Invoke-Source
    Assert ($report.ExitCode -eq 1 -and $global:WelaWefFixture.Slots['1'].Value -eq 'operator-existing' -and $global:WelaWefFixture.Writes.Count -eq 0) 'An occupied different SubscriptionManager slot is preserved and fails clearly'
    Reset-Fixture
    $global:WelaWefFixture.DriftKind='SubscriptionManager'; $global:WelaWefFixture.DriftAt=2
    $report=Invoke-Source
    Assert ($report.ExitCode -eq 1 -and $global:WelaWefFixture.Writes.Count -eq 0) 'Plan-to-initial-read registry drift blocks all slot writes'
    Reset-Fixture
    $global:WelaWefFixture.DriftKind='SubscriptionManager'; $global:WelaWefFixture.DriftAt=3
    $report=Invoke-Source
    Assert ($report.ExitCode -eq 1 -and $global:WelaWefFixture.Writes.Count -eq 0) 'Pre-write registry drift preserves the concurrent slot'
    Reset-Fixture
    $global:WelaWefFixture.Wsman['WSMan:\localhost\Client\Auth\Digest']='true'; $source.Hardening='ApplyASD'; Save-Configs
    $report=Invoke-Source
    Assert ($report.ExitCode -eq 0 -and $global:WelaWefFixture.Wsman['WSMan:\localhost\Client\Auth\Digest'] -eq 'false') 'Explicit ASD source hardening changes Digest and verifies readback'
    Reset-Fixture
    $global:WelaWefFixture.Wsman['WSMan:\localhost\Client\Auth\Digest']='true'; $global:WelaWefFixture.Policy['WSMan:\localhost\Client\Auth\Digest']='GPO'; $source.Hardening='ApplyASD'; Save-Configs
    $report=Invoke-Source
    Assert ($report.ExitCode -eq 1 -and $global:WelaWefFixture.Writes.Count -eq 0) 'GPO-owned noncompliant WSMan settings are not overridden'
    Reset-Fixture
    $global:WelaWefFixture.Admx=$false
    $report=Invoke-Source
    Assert ($report.ExitCode -eq 1 -and $global:WelaWefFixture.Writes.Count -eq 0) 'Unsupported local ADMX never receives a guessed registry write'
    Reset-Fixture
    $global:WelaWefFixture.Domain=$false
    $report=Invoke-Collector
    Assert ($report.ExitCode -eq 1 -and $global:WelaWefFixture.Writes.Count -eq 0) 'Unknown/non-domain collector identity prevents mutations'
    Reset-Fixture
    $global:WelaWefFixture.Listener=$false
    $report=Invoke-Collector
    Assert ($report.ExitCode -eq 1 -and $global:WelaWefFixture.Subs.Count -eq 0 -and $report.LocalConfigurationStatus -eq 'Incomplete') 'Missing collector listener blocks subscriptions and any configured claim'
    Reset-Fixture
    $global:WelaWefFixture.Ingress=$false
    $report=Invoke-Collector
    Assert ($report.ExitCode -eq 1 -and $global:WelaWefFixture.Subs.Count -eq 0) 'Disabled ingress definition cannot provision subscriptions'
    Reset-Fixture
    $global:WelaWefFixture.Wsman['WSMan:\localhost\Service\Auth\CbtHardeningLevel']='relaxed'
    $report=Invoke-Collector
    Assert ($report.ExitCode -eq 1 -and $global:WelaWefFixture.Writes.Count -eq 0) 'AssessOnly reports unmet ASD hardening and does not silently skip the prerequisite'
    Reset-Fixture
    $collector.Hardening='ApplyASD'; Save-Configs
    $global:WelaWefFixture.Wsman['WSMan:\localhost\Service\Auth\CbtHardeningLevel']='relaxed'
    $global:WelaWefFixture.Wsman['WSMan:\localhost\Shell\AllowRemoteShellAccess']='true'
    $global:WelaWefFixture.Forwarded=$false
    $report=Invoke-Collector -ResultsPath (Join-Path $temp 'collector-result.json')
    Assert ($report.ExitCode -eq 0 -and $global:WelaWefFixture.Subs.Count -eq 1) 'Verified collector creates only the selected explicit subscription'
    Assert ($null -eq $report.Subscriptions[0].ObservedSubscription.Xml.PSObject.Properties['PSDrive']) 'Observed XML strips reader ETS metadata before Windows PowerShell 5.1 JSON serialization'
    Assert ($report.Subscriptions[0].Runtime.Raw -eq 'Localized runtime fixture' -and $report.Subscriptions[0].EventArrival -eq 'Not tested') 'Native runtime evidence is retained without inventing successful arrivals'
    Assert ($report.Subscriptions[0].ChannelObservationLocation -like 'Collector only*') 'Collector channel inventory is not misrepresented as remote source state'
    $beforeWrites=$global:WelaWefFixture.Writes.Count; $script:backup=Join-Path $temp ([guid]::NewGuid().ToString('N')); $global:WelaWefFixture.Backup=$backup
    $report=Invoke-Collector
    Assert ($report.ExitCode -eq 0 -and $global:WelaWefFixture.Writes.Count -eq $beforeWrites) 'Equivalent existing subscriptions and hardened settings are idempotent'
    Reset-Fixture
    $model=Import-WelaWefConfig (Join-Path $temp 'collector.json') Collector
    $global:WelaWefFixture.Subs[$model.Subscriptions[0].Id]=$model.Subscriptions[0].Xml.Replace('<Enabled>true</Enabled>','<Enabled>false</Enabled>')
    $report=Invoke-Collector
    Assert ($report.ExitCode -eq 1 -and $global:WelaWefFixture.Writes.Count -eq 0) 'An existing disabled/different subscription is never silently updated'
    Assert ($report.Subscriptions[0].RequestedEnabled -and $report.Subscriptions[0].ObservedEnabled -eq $false) 'Inventory distinguishes an observed disabled subscription from the requested enabled definition'
    Reset-Fixture
    foreach($failure in @('Inventory','ReadXml')) {
        Reset-Fixture
        $model=Import-WelaWefConfig (Join-Path $temp 'collector.json') Collector
        $global:WelaWefFixture.Subs[$model.Subscriptions[0].Id]=$model.Subscriptions[0].Xml
        $global:WelaWefFixture.Fail=$failure
        $report=Invoke-Collector
        Assert ($report.ExitCode -eq 1 -and $global:WelaWefFixture.Writes.Count -eq 0) 'Incomplete enumeration or disappearing/unreadable XML cannot authorize creation'
        Assert ($null -eq $report.Subscriptions[0].ObservedSubscription -and $null -eq $report.Subscriptions[0].ObservedEnabled -and $report.Subscriptions[0].ObservationError) 'Read failure stays unknown rather than absent or disabled'
        Assert (@($report.Controls|Where-Object {$_.Kind -eq 'Subscription' -and $_.Status -eq 'Unknown'}).Count -eq 1) 'Partial observation remains an unknown control'
    }
    Reset-Fixture
    $model=Import-WelaWefConfig (Join-Path $temp 'collector.json') Collector
    $global:WelaWefFixture.Subs[$model.Subscriptions[0].Id]=$model.Subscriptions[0].Xml.Replace($model.Subscriptions[0].Id,'Different native ID')
    $report=Invoke-Collector
    Assert ($report.ExitCode -eq 1 -and $report.Subscriptions[0].ObservationError -match 'identity differs' -and $global:WelaWefFixture.Writes.Count -eq 0) 'Mismatched native XML identity cannot become selected subscription evidence'
    Reset-Fixture
    $global:WelaWefFixture.Fail='false-subscription'
    $report=Invoke-Collector
    Assert ($report.ExitCode -eq 1) 'A successful native exit without matching subscription readback fails'
    Reset-Fixture
    $global:WelaWefFixture.Fail='Subscription'
    $report=Invoke-Collector
    Assert ($report.ExitCode -eq 1 -and $global:WelaWefFixture.Subs.Count -eq 0) 'Native create failure remains incomplete'
    Reset-Fixture
    $report=Invoke-Collector Configure -DryRun
    Assert ($global:WelaWefFixture.Writes.Count -eq 0 -and -not (Test-Path $backup)) 'Collector dry-run creates no subscriptions, files or backup directory'
    Assert-Throws { Invoke-Source Plan -DryRun } 'Action-specific dry-run misuse is rejected before mutation'
    Reset-Fixture
    $global:WelaWefFixture.Services.WinRM.State='Stopped'
    $report=Invoke-Source Audit
    Assert ($global:WelaWefFixture.Reads.Wsman -eq $null -and $global:WelaWefFixture.Writes.Count -eq 0) 'Read-only audit never enters the WSMan provider while WinRM is stopped'
    Assert ($report.LocalConfigurationStatus -eq 'Incomplete') 'Stopped service audit cannot claim source configuration matches'
    Reset-Fixture
    $global:WelaWefFixture.Wsman['WSMan:\localhost\Service\Auth\Kerberos']='false'
    $report=Invoke-Collector
    Assert ($report.ExitCode -eq 1 -and $global:WelaWefFixture.Subs.Count -eq 0) 'Disabled Kerberos is an explicit collector prerequisite failure'
    Write-Host "WefDeployment.Tests: $script:count assertions passed."
} finally { $env:OS=$savedOS; Remove-Item -LiteralPath $temp -Recurse -Force }
