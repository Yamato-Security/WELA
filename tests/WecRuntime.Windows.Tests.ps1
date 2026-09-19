param([switch]$AllowDisposableSubscription)
$ErrorActionPreference='Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not $AllowDisposableSubscription -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {throw 'Native fixture requires explicit opt-in on a disposable GitHub-hosted Windows runner.'}
$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/WefSubscriptions.psm1') -Force
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/ControlApplicability.ps1')
. (Join-Path $repo 'scripts/WecRuntime.ps1')
$script:checks=0
function Assert($Condition,$Message) {if (-not $Condition) {throw $Message};$script:checks++}
function ServiceState {Get-CimInstance Win32_Service -Filter "Name='Wecsvc'" | Select-Object Name,State,StartMode}
function Key($Value) {ConvertTo-Json -InputObject $Value -Depth 16 -Compress}
function Subscriptions {@((Invoke-WelaNative 'wecutil.exe' @('es')).Output | ForEach-Object {$_.ToString().Trim()} | Where-Object {$_})}
$beforeService=ServiceState
if ($beforeService.State -notin @('Running','Stopped') -or $beforeService.StartMode -notin @('Auto','Manual','Disabled')) {throw 'Fixture requires stable existing service state.'}
$serviceKey='HKLM:\SYSTEM\CurrentControlSet\Services\Wecsvc'
$beforeDelayed=Get-WelaRegistryState $serviceKey DelayedAutoStart
$nonce=[guid]::NewGuid().ToString('N');$id='WELA-Runtime-Test-'+$nonce;$description='Owned disposable runtime fixture '+$nonce
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-wec-runtime-'+$nonce)
$null=New-Item -ItemType Directory -Path $temp
$created=$false;$beforeIds=$null
try {
    if ($beforeService.StartMode -eq 'Disabled') {Set-Service Wecsvc -StartupType Manual}
    if ($beforeService.State -eq 'Stopped') {Start-Service Wecsvc}
    $beforeIds=@(Subscriptions)
    if ($beforeIds -contains $id) {throw 'Unique fixture ID unexpectedly already exists.'}
    $xml=@"
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
<SubscriptionId>$id</SubscriptionId><SubscriptionType>SourceInitiated</SubscriptionType>
<Description>$description</Description><Enabled>false</Enabled>
<Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri><ConfigurationMode>Normal</ConfigurationMode>
<Query><![CDATA[<QueryList><Query Id="0" Path="Application"><Select>*[System[(EventID=1)]]</Select></Query></QueryList>]]></Query>
<ReadExistingEvents>false</ReadExistingEvents><TransportName>HTTP</TransportName><ContentFormat>Events</ContentFormat>
<Locale Language="en-US"/><LogFile>ForwardedEvents</LogFile>
<AllowedSourceDomainComputers>O:NSG:NSD:(A;;GA;;;S-1-5-21-111111111-222222222-333333333-1234)</AllowedSourceDomainComputers>
</Subscription>
"@
    $xmlPath=Join-Path $temp 'owned-disabled.xml';[IO.File]::WriteAllText($xmlPath,$xml,[Text.UTF8Encoding]::new($false))
    # Disabled, uniquely named and no real source: no listener/firewall/source deployment.
    $created=$true;$null=Invoke-WelaNative 'wecutil.exe' @('cs',$xmlPath)
    $definitionBefore=Get-WelaWecRuntimeDefinition $id;$serviceDuring=ServiceState
    $result=Invoke-WelaWecRuntime @($id) -ResultsPath (Join-Path $temp 'runtime.json')
    if ($result.ExitCode -ne 0) {throw (ConvertTo-Json $result -Depth 30)}
    $row=$result.Subscriptions[0]
    Assert ($row.Status -eq 'Observed' -and $row.Subscription.Activity -eq 'Disabled' -and -not $row.DefinitionBefore.Enabled) 'Actual disabled subscription is observed through the native runtime API.'
    Assert ($row.Subscription.Fields.Activity.NativeType -eq 2 -and $row.Subscription.Fields.Activity.Value -eq 1) 'Native activity uses documented UInt32 enum1.'
    Assert ($row.Subscription.Fields.LastError.NativeType -eq 2 -and $row.Subscription.Fields.LastError.Status -eq 'Observed') 'Native LastError is a typed observation, separate from API failure.'
    Assert ($row.SourceInventory.ReportedCount -eq 0 -and $row.Sources.Count -eq 0) 'Owned disabled subscription has no observed source history.'
    Assert ($row.CollectorBefore.ReaderSid -eq [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -and $row.CollectorBefore.Computer -eq [Environment]::MachineName) 'Actual reader and collector identities are captured.'
    Assert ($row.ReadyRuleCredit -eq 0 -and $row.EventArrival -eq 'Not tested') 'Disabled observation makes no forwarding/Ready claim.'
    Assert ((Get-WelaWecRuntimeDefinition $id).Key -ceq $definitionBefore.Key -and (Key (ServiceState)) -ceq (Key $serviceDuring)) 'Production runtime command changes no subscription or service state.'
    $missing=Read-WelaWecRuntimeValue ($id+'-Missing') $null 0
    Assert ($missing.State -eq 'Unknown' -and $missing.ErrorCode -ne 0) 'Actual native missing-subscription error is retained numerically.'
    $missingReport=Get-WelaWecRuntime ($id+'-Missing')
    Assert ($missingReport.Status -eq 'Unknown' -and $null -eq $missingReport.Subscription) 'Public observation cannot promote an absent subscription.'
    Write-Host "PASS: $script:checks actual read-only runtime assertions against an owned disabled subscription. No event source, connection or arrival is claimed."
} finally {
    $errors=@()
    try {
        if ($created -and @(Subscriptions) -contains $id) {
            $raw=(Invoke-WelaNative 'wecutil.exe' @('gs',$id,'/f:xml')).Diagnostic
            $doc=Read-WelaWefXml ([string]::Concat($raw));$ns=New-Object Xml.XmlNamespaceManager($doc.NameTable);$ns.AddNamespace('s','http://schemas.microsoft.com/2006/03/windows/events/subscription')
            $descriptions=@($doc.SelectNodes('/s:Subscription/s:Description',$ns))
            if ($descriptions.Count -ne 1 -or $descriptions[0].InnerText -cne $description) {throw 'Fixture ownership changed; refusing deletion.'}
            $null=Invoke-WelaNative 'wecutil.exe' @('ds',$id)
        }
        if ($null -ne $beforeIds -and (Key @($beforeIds | Sort-Object)) -cne (Key @(Subscriptions | Sort-Object))) {throw 'Subscription inventory was not restored.'}
    } catch {$errors+=$_.Exception.Message}
    try {
        if ($beforeService.State -eq 'Stopped' -and (Get-Service Wecsvc).Status -ne 'Stopped') {Stop-Service Wecsvc}
        if ($beforeService.StartMode -eq 'Disabled') {Set-Service Wecsvc -StartupType Disabled}
        if ((Key (Get-WelaRegistryState $serviceKey DelayedAutoStart)) -cne (Key $beforeDelayed)) {
            if ($beforeDelayed.ValueExists) {$null=New-ItemProperty -LiteralPath $serviceKey -Name DelayedAutoStart -Value $beforeDelayed.Value -PropertyType $beforeDelayed.Type -Force}
            else {Remove-ItemProperty -LiteralPath $serviceKey -Name DelayedAutoStart -ErrorAction Stop}
        }
        if ((Key (ServiceState)) -cne (Key $beforeService) -or (Key (Get-WelaRegistryState $serviceKey DelayedAutoStart)) -cne (Key $beforeDelayed)) {throw 'Wecsvc state/startup restoration differs.'}
    } catch {$errors+=$_.Exception.Message}
    if ($errors.Count) {throw "Fixture cleanup failed; preserve $temp : $($errors -join '; ')"}
    Remove-Item -LiteralPath $temp -Recurse -Force
    Write-Host 'PASS: original subscription inventory and Wecsvc state/startup restored; only the owned fixture was removed.'
}
$global:LASTEXITCODE=0
