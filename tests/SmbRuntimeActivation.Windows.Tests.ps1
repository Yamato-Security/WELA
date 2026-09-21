# Mutates only six audit flags on disposable GitHub-hosted Windows VMs. Never run on production.
$ErrorActionPreference='Stop'
if($env:OS -ne 'Windows_NT' -or $env:GITHUB_ACTIONS -ne 'true' -or $env:WELA_DISPOSABLE_SMB_ACTIVATION -ne 'true') {throw 'Explicit disposable GitHub Windows test opt-in is required.'}
$script:ScriptRoot=Split-Path $PSScriptRoot -Parent
. (Join-Path $script:ScriptRoot 'scripts/Configuration.ps1')
. (Join-Path $script:ScriptRoot 'scripts/SmbAuditing.ps1')
. (Join-Path $script:ScriptRoot 'scripts/WefArrival.ps1')
. (Join-Path $script:ScriptRoot 'scripts/SmbRuntimeActivation.ps1')
$computer=Get-CimInstance Win32_ComputerSystem
$os=Get-CimInstance Win32_OperatingSystem
if($computer.PartOfDomain -or $computer.DomainRole -ne 2 -or $os.ProductType -ne 3 -or [int]$os.BuildNumber -notin @(20348,26100)){throw 'Fixture requires an isolated member-class Server 2022/2025 host.'}
$evidence=Join-Path $env:RUNNER_TEMP ('wela-smb-runtime-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $evidence
$reportPath=Join-Path $evidence 'activation'
$cleanup=[ordered]@{Build=[int]$os.BuildNumber;Engine=$PSVersionTable.PSVersion.ToString();OriginalCaptured=$false;AuditFlagsRestored=$false;FullContextRestored=$false;NativeActivation=$false;UnsupportedRefusal=$false}
$original=$null
try {
    if([int]$os.BuildNumber -eq 20348) {
        $report=Invoke-WelaSmbRuntimeActivation -Action Activate -Auto -OutputPath $reportPath
        if($report.ExitCode -ne 1 -or $report.Diagnostic -notlike '*NotApplicable*' -or (Test-Path $reportPath)){throw 'Server 2022 activation was not refused before writes.'}
        $report | ConvertTo-Json -Depth 24 | Set-Content -LiteralPath (Join-Path $evidence 'refusal.json') -Encoding UTF8
        $global:LASTEXITCODE=0
        $null=& (Join-Path $script:ScriptRoot 'WELA.ps1') smb-runtime -SmbRuntimeAction Activate -SmbRuntimeOutputPath $reportPath -Auto
        if($LASTEXITCODE -ne 1 -or (Test-Path $reportPath)){throw 'Public CLI did not refuse unsupported Server 2022.'}
        $cleanup.UnsupportedRefusal=$true
        Write-Host 'PASS: actual Server 2022 native and public-CLI refusal, no output or setters.'
    }else{
        $original=Get-WelaSmbRuntimeState
        if(@(Get-WelaSmbRuntimePlan $original | Where-Object Status -eq BlockedPolicy).Count){throw 'Fixture will not overwrite a conflicting policy.'}
        $cleanup.OriginalCaptured=$true
        $original | ConvertTo-Json -Depth 24 | Set-Content -LiteralPath (Join-Path $evidence 'original.json') -Encoding UTF8
        foreach($definition in Get-WelaSmbAuditDefinitions) {
            $side=if($definition.Component -eq 'LanmanServer'){'Server'}else{'Client'}
            $command="SmbShare\Set-Smb${side}Configuration"
            $parameters=@{Force=$true;Confirm=$false;ErrorAction='Stop'};$parameters[$definition.Name]=$false
            $null=& $command @parameters
        }
        $prepared=Get-WelaSmbRuntimeState
        $expected=Get-WelaSmbRuntimeKey $original | ConvertFrom-Json
        foreach($definition in Get-WelaSmbAuditDefinitions) {
            $side=if($definition.Component -eq 'LanmanServer'){'Server'}else{'Client'}
            $expected.Configurations.$side.($definition.Name).Value=$false
        }
        if((Get-WelaSmbRuntimeKey $prepared) -cne (Get-WelaSmbRuntimeKey $expected)){throw 'Fixture preparation changed other settings or did not make audit flags False.'}
        $dry=Invoke-WelaSmbRuntimeActivation -Action Activate -Auto -DryRun -OutputPath $reportPath
        if($dry.ExitCode -ne 0 -or (Test-Path $reportPath) -or (Get-WelaSmbRuntimeKey (Get-WelaSmbRuntimeState)) -cne (Get-WelaSmbRuntimeKey $prepared)){throw 'Native dry-run changed context or wrote output.'}
        $global:LASTEXITCODE=0
        $cli=@(& (Join-Path $script:ScriptRoot 'WELA.ps1') smb-runtime -SmbRuntimeAction Activate -SmbRuntimeOutputPath $reportPath -Auto)
        if($LASTEXITCODE -ne 0){throw "Public CLI exited $LASTEXITCODE"}
        $report=Get-Content -Raw -LiteralPath (Join-Path $reportPath 'result.json') | ConvertFrom-Json
        if($report.ExitCode -ne 0 -or $report.Status -ne 'RuntimeAuditingActive' -or @($report.Results | Where-Object Status -eq Activated).Count -ne 6){throw "Native six-flag activation failed: $($report.Diagnostic)"}
        $active=Get-WelaSmbRuntimeState
        foreach($definition in Get-WelaSmbAuditDefinitions) {
            $side=if($definition.Component -eq 'LanmanServer'){'Server'}else{'Client'}
            $expected.Configurations.$side.($definition.Name).Value=$true
        }
        if((Get-WelaSmbRuntimeKey $active) -cne (Get-WelaSmbRuntimeKey $expected)){throw 'Activation did not preserve every unrelated configuration field and policy tuple.'}
        $repeat=Invoke-WelaSmbRuntimeActivation -Action Activate -Auto -OutputPath (Join-Path $evidence 'idempotent')
        if($repeat.ExitCode -ne 0 -or @($repeat.Results | Where-Object Status -eq AlreadyActive).Count -ne 6){throw 'Native idempotence failed.'}
        if(@(Get-ChildItem -LiteralPath $repeat.OutputPath -Filter '*-pending.json').Count){throw 'Idempotent run unexpectedly journaled a setter.'}
        $cleanup.NativeActivation=$true
        Write-Host 'PASS: actual Server 2025 public-CLI activation of all six native Boolean audit flags, dry-run, idempotence and preservation of all unrelated native configuration.'
    }
}finally{
    if($original) {
        $failures=@()
        foreach($definition in Get-WelaSmbAuditDefinitions) {
            try {
                $side=if($definition.Component -eq 'LanmanServer'){'Server'}else{'Client'}
                $command="SmbShare\Set-Smb${side}Configuration"
                $parameters=@{Force=$true;Confirm=$false;ErrorAction='Stop'};$parameters[$definition.Name]=[bool]$original.Configurations.$side.($definition.Name).Value
                $null=& $command @parameters
            }catch{$failures+=$_.Exception.Message}
        }
        $restored=Get-WelaSmbRuntimeState
        $restored | ConvertTo-Json -Depth 24 | Set-Content -LiteralPath (Join-Path $evidence 'restored.json') -Encoding UTF8
        $cleanup.AuditFlagsRestored=$failures.Count -eq 0
        $cleanup.FullContextRestored=(Get-WelaSmbRuntimeKey $restored) -ceq (Get-WelaSmbRuntimeKey $original)
        $cleanup | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence 'acceptance.json') -Encoding UTF8
        if(-not $cleanup.AuditFlagsRestored -or -not $cleanup.FullContextRestored){throw "Native SMB fixture cleanup mismatch: $($failures -join '; ')"}
        Write-Host 'PASS: exact native audit flags and full configuration/policy/source context restored.'
    }else{$cleanup | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence 'acceptance.json') -Encoding UTF8}
    Write-Host "Native SMB evidence: $evidence"
}
$global:LASTEXITCODE=0
