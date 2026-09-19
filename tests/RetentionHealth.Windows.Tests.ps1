# Actual local Windows reads only. No subscriptions, clocks, policies or ACLs changed.
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows retention smoke requires Windows.' }
$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/WefSubscriptions.psm1') -Force
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/RetentionHealth.ps1')
function Assert($Value,[string]$Message) { if (-not $Value) { throw "FAIL: $Message" } }
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-retention-readonly-' + [guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory $temp
$before=@(Get-CimInstance Win32_Service -Filter "Name='WinRM' OR Name='Wecsvc' OR Name='W32Time'" | Select-Object Name,StartMode,State | Sort-Object Name)
try {
    $config=[pscustomobject]@{ SchemaVersion=1; Role='Source'; Channels=@('System','Application'); MaxEventsPerChannel=5; SampleWindowMinutes=5; Archive=[pscustomobject]@{ DeclaredRetentionMonths=18; PolicyEvidence='Read-only smoke declaration, not compliance evidence'; Directory=$temp; MaxFiles=1; ReaderSids=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value) } }
    $configPath=Join-Path $temp 'config.json'; $config | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $configPath -Encoding UTF8
    $report=Invoke-WelaRetentionHealth -ConfigPath $configPath -ResultsPath (Join-Path $temp 'result.json') -HtmlPath (Join-Path $temp 'result.html')
    $json=Get-Content (Join-Path $temp 'result.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert ($json.Channels.Count -eq 2 -and $json.Channels[0].Buffer.MaximumBytes -gt 0) 'Actual local channel metadata survives public JSON export'
    Assert ($json.Channels[0].Rate.RecordCap -eq 5 -and $json.Channels[0].Rate.SampleCount -le 5) 'Native sampling obeys the declared cap'
    Assert ($json.RetentionCompliance -eq 'Not established' -and $json.Time.SynchronizationHealth -eq 'Unknown') 'Real read success does not promote compliance/time claims'
    Assert ($json.Archive.Status -eq 'LocalInventoryObserved' -and $json.Archive.ObservedDirectory.SecurityDescriptor) 'Actual owned local directory ACL is inventoried'
    Assert ($json.Archive.IntendedReaders[0].EffectiveReadAccess -eq 'Not tested') 'Directory ACE evidence remains distinct from reader-token access'
    $config.Role='Collector'; $config.Channels=@('ForwardedEvents'); $config | Add-Member NoteProperty SubscriptionIds @('WELA ReadOnly Smoke Missing Subscription')
    $config | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $configPath -Encoding UTF8
    $collector=Invoke-WelaRetentionHealth -ConfigPath $configPath
    Assert ($collector.Subscriptions.Count -eq 1 -and $collector.Subscriptions[0].DeliveryHealth -eq 'Unknown') 'Missing collector subscription remains unknown and does not trigger provisioning'
    foreach ($bad in @('\\server\share','C:\..\archive','C:relative','\\?\C:\archive')) {
        $caught=$false; try { Get-WelaRetentionArchiveDirectory $bad | Out-Null } catch { $caught=$true }; Assert $caught 'Remote/device/ambiguous archive paths are rejected before inventory'
    }
    $after=@(Get-CimInstance Win32_Service -Filter "Name='WinRM' OR Name='Wecsvc' OR Name='W32Time'" | Select-Object Name,StartMode,State | Sort-Object Name)
    Assert (($before | ConvertTo-Json -Compress) -ceq ($after | ConvertTo-Json -Compress)) 'Read-only reports preserve the observed service states and start modes'
    Write-Host 'RetentionHealth.Windows.Tests: actual native source/collector reads, archive ACL and export smoke passed; no arrival/rollover/time-sync lab claim.'
} finally { Remove-Item -LiteralPath $temp -Recurse -Force }
# Handled native query failures are report evidence, not failed script assertions.
$global:LASTEXITCODE=0
