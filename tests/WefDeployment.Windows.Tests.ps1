# Actual Windows read-only paths only. No listener/service/policy/subscription writes.
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows read-only smoke requires Windows.' }
$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/WefSubscriptions.psm1') -Force
Import-Module (Join-Path $repo 'modules/NativeProviders.psm1') -Force
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/NativeChannelConfiguration.ps1')
. (Join-Path $repo 'scripts/WefDeployment.ps1')
$script:ScriptRoot=$repo
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-wef-readonly-' + [guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory $temp
function Assert($Value,[string]$Message) { if (-not $Value) { throw "FAIL: $Message" } }
$before=@(Get-CimInstance Win32_Service -Filter "Name='WinRM' OR Name='Wecsvc'" | Select-Object Name,StartMode,State | Sort-Object Name)
try {
    foreach ($role in @('Source','Collector')) {
        $out=Join-Path $temp ($role + '.json')
        $report=Invoke-WelaWefCommand -Role $role -Action Audit -ConfigPath (Join-Path $repo ('config/wef-examples/' + $role.ToLowerInvariant() + '.json')) -ResultsPath $out
        $json=Get-Content -LiteralPath $out -Raw | ConvertFrom-Json
        Assert ($json.Role -eq $role -and $json.Action -eq 'Audit') 'Real public audit path exports its role/action'
        Assert ($json.Subscriptions.Count -eq 1 -and $json.Subscriptions[0].EffectiveSourceReadAccess -eq 'Not tested') 'Actual channel read does not claim effective forwarding access'
        Assert ($json.Subscriptions[0].SourceChannels[0].Name -eq 'Security') 'Actual native Security channel metadata is inventoried'
        Assert ($json.Subscriptions[0].ForwardedSigmaCoverage -eq 'Not assessed') 'No rule credit is inferred by native WEF audit'
    }
    # The ADMX adapter uses the actual host definition; unsupported layouts are
    # recorded as unmet, rather than allowing a registry write from this smoke.
    $sourceJson=Get-Content (Join-Path $temp 'Source.json') -Raw | ConvertFrom-Json
    Assert (@($sourceJson.Prerequisites | Where-Object Name -eq 'Local SubscriptionManager ADMX mapping').Count -eq 1) 'OS ADMX mapping is explicitly assessed'
    $after=@(Get-CimInstance Win32_Service -Filter "Name='WinRM' OR Name='Wecsvc'" | Select-Object Name,StartMode,State | Sort-Object Name)
    Assert (($before | ConvertTo-Json -Compress) -ceq ($after | ConvertTo-Json -Compress)) 'Read-only audit leaves both service start modes and states unchanged'
    Write-Host 'WEF Windows read-only smoke passed; no subscription deployment or event delivery is claimed.'
} finally { Remove-Item -LiteralPath $temp -Recurse -Force }
