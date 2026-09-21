$ErrorActionPreference='Stop'
$script:ScriptRoot=Split-Path $PSScriptRoot -Parent
. (Join-Path $script:ScriptRoot 'scripts/Configuration.ps1')
. (Join-Path $script:ScriptRoot 'scripts/SmbAuditing.ps1')
. (Join-Path $script:ScriptRoot 'scripts/WefArrival.ps1')
. (Join-Path $script:ScriptRoot 'scripts/SmbRuntimeActivation.ps1')
$script:checks=0
function Assert($Condition,[string]$Message){if(-not $Condition){throw "FAIL: $Message"};$script:checks++}
function Reject([scriptblock]$Code,[string]$Message){$failed=$false;try{& $Code}catch{$failed=$true};Assert $failed $Message}
Reject {Set-WelaSmbRuntimeFlag 'LanmanWorkstation/EnableInsecureGuestLogons'} 'security parameter refused by actual setter adapter'
Reject {Set-WelaSmbRuntimeFlag 'LanmanServer/auditinsecureguestlogon'} 'mis-cased control refused'
function FixtureConfiguration {
    param([string]$Side='Server')
    $component=if($Side -eq 'Server'){'LanmanServer'}else{'LanmanWorkstation'}
    $properties=@(Get-WelaSmbAuditDefinitions | Where-Object Component -eq $component | ForEach-Object {[pscustomobject]@{Name=$_.Name;Value=$false;CimType='Boolean'}})
    $properties+=[pscustomobject]@{Name='RequireSecuritySignature';Value=$true;CimType='Boolean'}
    [pscustomobject]@{CimClass=[pscustomobject]@{CimClassName="MSFT_Smb${Side}Configuration"};CimInstanceProperties=$properties}
}
$native=FixtureConfiguration
$config=ConvertTo-WelaSmbRuntimeConfiguration $native Server
Assert ($config.RequireSecuritySignature.Value -eq $true -and $config.AuditInsecureGuestLogon.Value -eq $false) 'native typed security and audit properties retained'
$native.CimInstanceProperties[0].Value='False'
Reject {ConvertTo-WelaSmbRuntimeConfiguration $native Server} 'string audit Boolean rejected'
$native=FixtureConfiguration;$native.CimInstanceProperties[0].CimType='String'
Reject {ConvertTo-WelaSmbRuntimeConfiguration $native Server} 'wrong native CIM type rejected'
$native=FixtureConfiguration;$native.CimClass.CimClassName='MSFT_AnotherConfiguration'
Reject {ConvertTo-WelaSmbRuntimeConfiguration $native Server} 'wrong native class rejected'
$native=FixtureConfiguration;$native.CimInstanceProperties+=[pscustomobject]@{Name='Mystery';Value=[pscustomobject]@{a=1};CimType='Instance'}
Reject {ConvertTo-WelaSmbRuntimeConfiguration $native Server} 'unknown unrelated configuration remains unverified'

$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-smb-activation-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $root
$script:receiptWriter=${function:Write-WelaSmbRuntimeReceipt}
function Reset-Fixture {
    $policies=[ordered]@{}
    foreach($definition in Get-WelaSmbAuditDefinitions){$policies["$($definition.Component)/$($definition.Name)"]=[pscustomobject]@{Policy=[pscustomobject]@{KeyExists=$false;ValueExists=$false;Type=$null;Value=$null}}}
    $script:fixture=[pscustomobject][ordered]@{Computer='fixture';Host=[pscustomobject]@{Build=26100};Commands='native';Sources='hash';Policies=[pscustomobject]$policies;Configurations=[pscustomobject]@{Server=(ConvertTo-WelaSmbRuntimeConfiguration (FixtureConfiguration Server) Server);Client=(ConvertTo-WelaSmbRuntimeConfiguration (FixtureConfiguration Client) Client)}}
    $script:writes=0;$script:reads=0;$script:driftRead=0;$script:failWrite=0;$script:securityDrift=$false;$script:receiptFail=$false;$script:promptDrift=$false
    $script:out=Join-Path $root ([guid]::NewGuid().ToString('N'))
}
function Get-WelaSmbRuntimeState {
    $script:reads++
    if($script:reads -eq $script:driftRead){$script:fixture.Sources='changed'}
    Get-WelaSmbRuntimeKey $script:fixture | ConvertFrom-Json
}
function Write-WelaSmbRuntimeReceipt {
    param($Root,$Name,$Value)
    if($script:receiptFail -and $Name -eq '1-pending.json'){throw 'Injected durable-write failure'}
    & $script:receiptWriter $Root $Name $Value
}
function Set-WelaSmbRuntimeFlag {
    param($Id)
    $script:writes++
    Assert (Test-Path (Join-Path $script:out "$($script:writes)-pending.json")) 'pending receipt exists before setter'
    if($script:writes -eq $script:failWrite){throw 'Injected native setter failure'}
    $parts=$Id.Split('/');$side=if($parts[0] -eq 'LanmanServer'){'Server'}else{'Client'}
    $script:fixture.Configurations.$side.($parts[1]).Value=$true
    if($script:securityDrift){$script:fixture.Configurations.Server.RequireSecuritySignature.Value=$false}
}
function Read-Host {param($Prompt) if($script:promptDrift){$script:fixture.Sources='changed at prompt'};'y'}
try {
    Reset-Fixture
    $plan=Invoke-WelaSmbRuntimeActivation
    Assert ($plan.Status -eq 'Planned' -and $plan.Controls.Count -eq 6 -and $script:writes -eq 0) 'default Plan is six read-only audit controls'
    Assert (-not (Test-Path $script:out)) 'Plan creates no evidence directory'
    $dry=Invoke-WelaSmbRuntimeActivation -Action Activate -DryRun -OutputPath $script:out
    Assert ($dry.Status -eq 'DryRun' -and $script:writes -eq 0 -and -not (Test-Path $script:out)) 'DryRun does not write'
    Reject {Invoke-WelaSmbRuntimeActivation -Action Plan -Auto} 'irrelevant Plan consent rejected'
    Reject {Invoke-WelaSmbRuntimeActivation -Action Plan -DryRun} 'invalid dry run action rejected'
    $id='LanmanServer/AuditInsecureGuestLogon'
    foreach($value in @(0,'1',2)) {
        Reset-Fixture;$script:fixture.Policies.$id.Policy=[pscustomobject]@{KeyExists=$true;ValueExists=$true;Type='DWord';Value=$value}
        $report=Invoke-WelaSmbRuntimeActivation -Action Activate -Auto -OutputPath $script:out
        Assert ($report.ExitCode -eq 1 -and $script:writes -eq 0 -and -not (Test-Path $script:out)) 'conflicting or mistyped policy stops all mutations'
    }
    Reset-Fixture;$script:fixture.Policies.$id.Policy=[pscustomobject]@{KeyExists=$true;ValueExists=$true;Type='String';Value=1}
    Assert ((Invoke-WelaSmbRuntimeActivation).ExitCode -eq 1) 'wrong registry kind blocks'
    Reset-Fixture;$script:fixture.Policies.$id.Policy=[pscustomobject]@{KeyExists=$true;ValueExists=$true;Type='DWord';Value=1}
    Assert ((Invoke-WelaSmbRuntimeActivation).ExitCode -eq 0) 'existing enabled policy is compatible'

    Reset-Fixture
    $report=Invoke-WelaSmbRuntimeActivation -Action Activate -Auto -OutputPath $script:out
    Assert ($report.ExitCode -eq 0 -and $report.Status -eq 'RuntimeAuditingActive' -and $script:writes -eq 6) "six native activations succeed: $($report.Diagnostic)"
    Assert (@($report.Results | Where-Object Status -eq Activated).Count -eq 6) 'all six report confirmed activation'
    Assert ((Get-ChildItem -LiteralPath $script:out -File).Count -eq 14) 'plan, six pending, six confirmed, final result retained'
    Assert ($report.After.Configurations.Server.RequireSecuritySignature.Value -eq $true) 'security property preserved'
    Assert ($report.ReadyRuleCredit -eq 0 -and $report.EventGeneration -eq 'Not tested') 'activation grants no event or rule proof'
    $prior=Get-Content -Raw -LiteralPath (Join-Path $script:out 'result.json')
    $second=Invoke-WelaSmbRuntimeActivation -Action Activate -Auto -OutputPath $script:out
    Assert ($second.ExitCode -eq 1 -and (Get-Content -Raw -LiteralPath (Join-Path $script:out 'result.json')) -ceq $prior) 'existing evidence is never overwritten'
    $script:out=Join-Path $root ([guid]::NewGuid().ToString('N'));$script:writes=0
    $repeat=Invoke-WelaSmbRuntimeActivation -Action Activate -Auto -OutputPath $script:out
    Assert ($repeat.ExitCode -eq 0 -and $script:writes -eq 0 -and @($repeat.Results | Where-Object Status -eq AlreadyActive).Count -eq 6) 'idempotence requires no setters'

    Reset-Fixture;$script:failWrite=2
    $partial=Invoke-WelaSmbRuntimeActivation -Action Activate -Auto -OutputPath $script:out
    Assert ($partial.ExitCode -eq 1 -and $script:writes -eq 2) 'partial native failure stops remaining writes'
    Assert ($partial.Results[0].Status -eq 'Activated' -and $partial.Results[1].Status -eq 'Failed' -and $partial.Results[2].Status -eq 'Skipped') 'partial outcomes preserved'
    Assert ((Test-Path (Join-Path $script:out '1-confirmed.json')) -and -not (Test-Path (Join-Path $script:out '2-confirmed.json'))) 'failed operation is never confirmed'
    foreach($read in @(2,3,20)) {
        Reset-Fixture;$script:driftRead=$read
        $drift=Invoke-WelaSmbRuntimeActivation -Action Activate -Auto -OutputPath $script:out
        Assert ($drift.ExitCode -eq 1) 'fresh/prewrite/final source drift fails closed'
        if($read -lt 4){Assert ($script:writes -eq 0) 'prewrite drift performs no setter'}
    }
    Reset-Fixture;$script:promptDrift=$true
    $drift=Invoke-WelaSmbRuntimeActivation -Action Activate -OutputPath $script:out
    Assert ($drift.ExitCode -eq 1 -and $script:writes -eq 0) 'prompt-time drift refused'
    Reset-Fixture;$script:securityDrift=$true
    $drift=Invoke-WelaSmbRuntimeActivation -Action Activate -Auto -OutputPath $script:out
    Assert ($drift.ExitCode -eq 1 -and $script:writes -eq 1 -and -not (Test-Path (Join-Path $script:out '1-confirmed.json'))) 'unrelated security delta prevents confirmation'
    Reset-Fixture;$script:receiptFail=$true
    $failed=Invoke-WelaSmbRuntimeActivation -Action Activate -Auto -OutputPath $script:out
    Assert ($failed.ExitCode -eq 1 -and $script:writes -eq 0) 'failed durable intent blocks setter'
    Assert (Test-Path (Join-Path $script:out 'result.json')) 'partial diagnostic survives pending-write failure'
    Write-Host "PASS: $script:checks SMB runtime activation assertions"
}finally{Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue}
