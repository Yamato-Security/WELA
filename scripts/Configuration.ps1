# Execution helpers for configure. Compatible with Windows PowerShell 5.1.
function Invoke-WelaNative {
    param([string]$FilePath, [string[]]$Arguments)
    # Windows PowerShell sends native stderr through the error stream. Collect it
    # without treating stderr alone as failure; the process exit code is decisive.
    $ErrorActionPreference = 'Continue'
    $PSNativeCommandUseErrorActionPreference = $false
    $null = Get-Command $FilePath -ErrorAction Stop
    $global:LASTEXITCODE = $null
    $output = @(& $FilePath @Arguments 2>&1)
    $exitCode = $global:LASTEXITCODE # Capture immediately, before invoking anything else.
    $diagnostic = ($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
    if ($null -eq $exitCode -or $exitCode -ne 0) {
        throw "$FilePath $($Arguments -join ' ') failed (exit: $exitCode). $diagnostic"
    }
    [pscustomobject]@{ ExitCode = $exitCode; Output = $output; Diagnostic = $diagnostic }
}

function New-WelaConfigurationContext {
    param([switch]$Auto, [switch]$DryRun, [string]$BackupPath)
    if (-not $DryRun) {
        if (-not $BackupPath) {
            $BackupPath = Join-Path $script:ScriptRoot ("wela-backup-{0}-{1}" -f (Get-Date -Format 'yyyyMMdd-HHmmss'), [guid]::NewGuid().ToString('N'))
        }
        # Refuse reuse: a prior run's recovery evidence must never be overwritten.
        $null = New-Item -ItemType Directory -Path $BackupPath -ErrorAction Stop
        $BackupPath = (Resolve-Path -LiteralPath $BackupPath -ErrorAction Stop).Path
    }
    [pscustomobject]@{
        Auto = [bool]$Auto; DryRun = [bool]$DryRun; BackupPath = $BackupPath
        Results = New-Object 'System.Collections.Generic.List[object]'
        Checks = New-Object 'System.Collections.Generic.List[object]'
    }
}

function Invoke-WelaConfigurationControl {
    param($Context, [string]$Id, [string]$Kind, $Target, $Desired,
          [scriptblock]$Read, [scriptblock]$Compliant, [scriptblock]$Apply,
          [string]$Description = '')
    $result = [pscustomobject][ordered]@{
        Id = $Id; Kind = $Kind; Target = $Target; Desired = $Desired
        Before = $null; After = $null; Status = 'Failed'; Diagnostic = ''
    }
    try {
        $result.Before = & $Read
        if (& $Compliant $result.Before) {
            $result.Status = 'AlreadyCompliant'
            $result.After = $result.Before
        } elseif ($Context.DryRun) {
            $result.Status = 'Skipped'; $result.Diagnostic = 'Dry run: change required; no write or restart performed.'
        } else {
            $proceed = $Context.Auto
            if (-not $proceed) {
                $response = Read-Host "$Id : $Description Apply this change? (Y/n)"
                $proceed = ($response -eq '' -or $response -match '^[Yy]$')
            }
            if (-not $proceed) {
                $result.Status = 'Skipped'; $result.Diagnostic = 'Declined by operator.'
            } else {
                # Persist the exact pre-change value before any mutation. A journal
                # failure stops this control, including service restarts.
                $entry = [ordered]@{
                    Version = 1; ComputerName = $env:COMPUTERNAME
                    RecordedUtc = [DateTime]::UtcNow.ToString('o')
                    Id = $Id; Kind = $Kind; Target = $Target
                    Before = $result.Before; Desired = $Desired
                }
                $entry | ConvertTo-Json -Depth 12 -Compress |
                    Add-Content -LiteralPath (Join-Path $Context.BackupPath 'before.jsonl') -Encoding UTF8 -ErrorAction Stop
                $applied = @(& $Apply)
                $result.Diagnostic = ($applied | ForEach-Object {
                    if ($_.PSObject.Properties['Diagnostic']) { $_.Diagnostic } else { $_.ToString() }
                }) -join [Environment]::NewLine
                $result.After = & $Read
                if (-not (& $Compliant $result.After)) {
                    throw "Post-apply verification did not match the requested state. $($result.Diagnostic)"
                }
                $result.Status = 'Applied'
            }
        }
        if ($result.Status -in @('Applied', 'AlreadyCompliant')) {
            $Context.Checks.Add([pscustomobject]@{ Result = $result; Read = $Read; Compliant = $Compliant })
        }
    } catch {
        $result.Status = 'Failed'; $result.Diagnostic = $_.ToString()
    }
    $Context.Results.Add($result)
    $color = if ($result.Status -eq 'Failed') { 'Red' } elseif ($result.Status -eq 'Skipped') { 'Yellow' } else { 'Green' }
    Write-Host "[$($result.Status)] $Id $($result.Diagnostic)" -ForegroundColor $color
}

function Complete-WelaConfiguration {
    param($Context, [string]$ResultsPath)
    # A second read detects a value that was compliant earlier but changed during
    # this run. It does not establish whether GPO or another writer caused drift.
    foreach ($check in $Context.Checks) {
        try {
            $check.Result.After = & $check.Read
            if (-not (& $check.Compliant $check.Result.After)) {
                $check.Result.Status = 'Overridden'
                $check.Result.Diagnostic = 'State was compliant earlier but changed before the final check; cause unknown.'
            }
        } catch {
            $check.Result.Status = 'Failed'
            $check.Result.Diagnostic = "Final verification failed: $_"
        }
    }
    $failed = @($Context.Results | Where-Object { $_.Status -in @('Failed', 'Overridden') }).Count
    $skipped = @($Context.Results | Where-Object { $_.Status -eq 'Skipped' }).Count
    $report = [pscustomobject][ordered]@{
        ExitCode = $(if ($failed) { 1 } else { 0 }); DryRun = $Context.DryRun
        BackupPath = $Context.BackupPath; Failed = $failed; Skipped = $skipped
        Results = @($Context.Results.ToArray())
    }
    if ($ResultsPath) {
        try { $report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $ResultsPath -Encoding UTF8 -ErrorAction Stop }
        catch { $report.ExitCode = 1; Write-Host "[Failed] Writing results: $_" -ForegroundColor Red }
    }
    if ($report.ExitCode) { Write-Host "Configuration incomplete: $failed failed or overridden control(s). Review results and recovery journal." -ForegroundColor Red }
    elseif ($Context.DryRun) { Write-Host 'Dry run completed. No Windows configuration was changed.' -ForegroundColor Cyan }
    elseif ($skipped) { Write-Host "Configuration completed with $skipped skipped control(s)." -ForegroundColor Yellow }
    else { Write-Host 'Configuration completed; all requested controls verified.' -ForegroundColor Green }
    return $report
}

function Set-WelaEventLogControl {
    param($Context, [string]$Log, [string]$Property, $Desired)
    $read = { (Get-WinEvent -ListLog $Log -ErrorAction Stop).$Property }.GetNewClosure()
    $test = if ($Property -eq 'MaximumSizeInBytes') {
        { param($value) $value -ge $Desired }.GetNewClosure()
    } else { { param($value) $value -eq $Desired }.GetNewClosure() }
    $argument = if ($Property -eq 'MaximumSizeInBytes') { "/ms:$Desired" } else { '/e:true' }
    $apply = { Invoke-WelaNative -FilePath 'wevtutil.exe' -Arguments @('sl', $Log, $argument) }.GetNewClosure()
    Invoke-WelaConfigurationControl -Context $Context -Id "EventLog/$Log/$Property" -Kind EventLog `
        -Target @{ Log = $Log; Property = $Property } -Desired $Desired -Read $read -Compliant $test -Apply $apply
}

function Get-WelaRegistryState {
    param([string]$Path, [string]$Name)
    if (-not (Test-Path -LiteralPath $Path -ErrorAction Stop)) {
        return [pscustomobject]@{ KeyExists = $false; ValueExists = $false; Value = $null; Type = $null }
    }
    $key = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($key.GetValueNames() -notcontains $Name) {
        return [pscustomobject]@{ KeyExists = $true; ValueExists = $false; Value = $null; Type = $null }
    }
    [pscustomobject]@{
        KeyExists = $true; ValueExists = $true
        Value = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        Type = $key.GetValueKind($Name).ToString()
    }
}

function Set-WelaRegistryControl {
    param($Context, [string]$Path, [string]$Name, $Value, [string]$Type = 'DWord')
    $read = { Get-WelaRegistryState -Path $Path -Name $Name }.GetNewClosure()
    $test = { param($state) $state.ValueExists -and $state.Value -eq $Value -and $state.Type -eq $Type }.GetNewClosure()
    $apply = {
        if (-not (Test-Path -LiteralPath $Path -ErrorAction Stop)) {
            $null = New-Item -Path $Path -ErrorAction Stop
        }
        Set-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -Type $Type -ErrorAction Stop
    }.GetNewClosure()
    Invoke-WelaConfigurationControl -Context $Context -Id "Registry/$Path/$Name" -Kind Registry `
        -Target @{ Path = $Path; Name = $Name } -Desired @{ Value = $Value; Type = $Type } `
        -Read $read -Compliant $test -Apply $apply
}

function Get-WelaAuditPolicyMask {
    param([string]$Guid)
    $native = Invoke-WelaNative -FilePath 'auditpol.exe' -Arguments @('/get', "/subcategory:{$Guid}", '/r')
    # Column order is stable; names and Inclusion Setting text are localized.
    $rows = $native.Output | ConvertFrom-Csv -Header Machine, Target, Name, Guid, Inclusion, Exclusion, SettingValue
    $row = @($rows | Where-Object { $_.Guid -and $_.Guid.Trim('{}') -eq $Guid })
    if ($row.Count -ne 1 -or $row[0].SettingValue -notmatch '^[0-3]$') {
        throw "auditpol returned no unambiguous numeric setting for $Guid. $($native.Diagnostic)"
    }
    return [int]$row[0].SettingValue
}

function Set-WelaAuditPolicyControl {
    param($Context, $Policy)
    $guid = $Policy.GUID
    $read = { Get-WelaAuditPolicyMask -Guid $guid }.GetNewClosure()
    $apply = { Invoke-WelaNative -FilePath 'auditpol.exe' -Arguments @('/set', "/subcategory:{$guid}", '/success:enable', '/failure:enable') }.GetNewClosure()
    Invoke-WelaConfigurationControl -Context $Context -Id "AuditPolicy/$($Policy.Name)" -Kind AuditPolicy `
        -Target @{ Guid = $guid } -Desired 3 -Read $read -Compliant { param($value) $value -eq 3 } -Apply $apply
}

function Set-WelaCertificateAuditControl {
    param($Context)
    $root = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
    try {
        if (-not (Test-Path -LiteralPath $root -ErrorAction Stop)) {
            $Context.Results.Add([pscustomobject]@{ Id = 'ADCS/AuditFilter'; Kind = 'CertificateService'; Target = $root; Desired = 127; Before = $null; After = $null; Status = 'Skipped'; Diagnostic = 'No configured local CA.' })
            return
        }
        $caName = (Get-ItemProperty -LiteralPath $root -Name Active -ErrorAction Stop).Active
        if (-not $caName) { throw 'CA configuration has no active CA name.' }
        $path = Join-Path $root $caName
        $read = {
            [pscustomobject]@{
                Registry = Get-WelaRegistryState -Path $path -Name AuditFilter
                ServiceStatus = (Get-Service -Name CertSvc -ErrorAction Stop).Status.ToString()
            }
        }.GetNewClosure()
        $test = { param($value) $value.Registry.ValueExists -and $value.Registry.Value -eq 127 -and $value.ServiceStatus -eq 'Running' }
        $apply = {
            $state = Get-Service -Name CertSvc -ErrorAction Stop
            if ($state.Status -ne 'Running') { throw 'CertSvc is not running; refusing to start a previously stopped CA. Start it deliberately before retrying.' }
            Invoke-WelaNative -FilePath 'certutil.exe' -Arguments @('-setreg', 'CA\AuditFilter', '127')
            Restart-Service -Name CertSvc -Force -ErrorAction Stop
            $service = Get-Service -Name CertSvc -ErrorAction Stop
            $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
        }
        Invoke-WelaConfigurationControl -Context $Context -Id 'ADCS/AuditFilter' -Kind CertificateService `
            -Target @{ Path = $path; Name = 'AuditFilter'; Service = 'CertSvc' } -Desired 127 `
            -Read $read -Compliant $test -Apply $apply -Description 'Set AuditFilter=127 and restart Certificate Services.'
    } catch {
        $Context.Results.Add([pscustomobject]@{ Id = 'ADCS/AuditFilter'; Kind = 'CertificateService'; Target = $root; Desired = 127; Before = $null; After = $null; Status = 'Failed'; Diagnostic = $_.ToString() })
    }
}
