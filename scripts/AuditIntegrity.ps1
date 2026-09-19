# Explicit source-profile audit integrity. Direct assignments are not token membership.
function Initialize-WelaIntegrityNative {
    if (-not ('Wela.AuditIntegrityNative' -as [type])) {
        Add-Type -Path (Join-Path $PSScriptRoot 'AuditIntegrityNative.cs') -ErrorAction Stop
    }
}
function Get-WelaIntegrityHolders {
    param([ValidateSet('SeAuditPrivilege','SeSecurityPrivilege')][string]$Right)
    Initialize-WelaIntegrityNative
    return ,@([Wela.AuditIntegrityNative]::Holders($Right))
}
function Get-WelaIntegrityAccountRights {
    param([string]$Sid)
    Initialize-WelaIntegrityNative
    return ,@([Wela.AuditIntegrityNative]::Rights($Sid))
}
function Set-WelaIntegrityAccountRight {
    param([string]$Sid,[ValidateSet('SeAuditPrivilege','SeSecurityPrivilege')][string]$Right,[bool]$Grant)
    Initialize-WelaIntegrityNative
    [Wela.AuditIntegrityNative]::Change($Sid,$Right,$Grant)
}
function Get-WelaIntegrityHost {
    if ($env:OS -ne 'Windows_NT') { throw 'Audit integrity requires Windows.' }
    $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ($os.ProductType -notin @(1,2,3) -or $computer.DomainRole -notin @(0,1,2,3,4,5) -or $null -eq $computer.PartOfDomain -or [string]$os.BuildNumber -notmatch '^\d+$') { throw 'Unknown Windows role/build.' }
    $role=$null
    if ($os.ProductType -eq 1 -and $computer.DomainRole -in @(0,1)) { $role='Client' }
    elseif ($os.ProductType -eq 2 -and $computer.DomainRole -in @(4,5) -and $computer.PartOfDomain) { $role='DomainController' }
    elseif ($os.ProductType -eq 3 -and $computer.DomainRole -eq 3 -and $computer.PartOfDomain) { $role='MemberServer' }
    elseif ($os.ProductType -eq 3 -and $computer.DomainRole -eq 2 -and -not $computer.PartOfDomain) { $role='StandaloneServer' }
    if (-not $role -or ($computer.DomainRole -eq 1 -and -not $computer.PartOfDomain) -or ($computer.DomainRole -eq 0 -and $computer.PartOfDomain)) { throw 'Conflicting Windows role observations.' }
    if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit PowerShell for this workflow.' }
    $ca='Unknown'
    try { $ca=if (@(Get-CimInstance Win32_Service -Filter "Name='CertSvc'" -ErrorAction Stop).Count) { 'Installed' } else { 'NotInstalled' } } catch { }
    [pscustomobject]@{Status='Known';ComputerName=[string]$computer.Name;Role=$role;Build=[int]$os.BuildNumber;DomainJoined=[bool]$computer.PartOfDomain;DomainRole=[int]$computer.DomainRole;CertificateAuthority=$ca}
}
function Get-WelaIntegritySnapshot {
    param([string[]]$ObserveSids=@())
    $errors=@();$hostState=$null;$rights=@();$accounts=@();$crash=$null
    try { $hostState=Get-WelaIntegrityHost } catch { $hostState=[pscustomobject]@{Status='Unknown';Diagnostic=$_.Exception.Message};$errors+=$_.Exception.Message }
    if ($hostState.Status -eq 'Known') {
        foreach ($right in @('SeAuditPrivilege','SeSecurityPrivilege')) {
            try { $holders=@(Get-WelaIntegrityHolders $right | ForEach-Object {$_} | Sort-Object -Unique);$rights+=[pscustomobject]@{Name=$right;Holders=$holders;Status='Known'} }
            catch { $rights+=[pscustomobject]@{Name=$right;Holders=@();Status='Unknown'};$errors+="$right : $($_.Exception.Message)" }
        }
        $sids=@(@('S-1-5-19','S-1-5-20','S-1-5-32-544') + @($rights | ForEach-Object {$_.Holders}) + @($ObserveSids) | Sort-Object -Unique)
        foreach ($sid in $sids) {
            try { $assigned=@(Get-WelaIntegrityAccountRights $sid | ForEach-Object {$_} | Sort-Object -Unique);$accounts+=[pscustomobject]@{Sid=$sid;Rights=$assigned;Status='Known'} }
            catch { $accounts+=[pscustomobject]@{Sid=$sid;Rights=@();Status='Unknown'};$errors+="$sid : $($_.Exception.Message)" }
        }
        if (-not $errors.Count) {
            foreach ($right in $rights) {
                $fromAccounts=@($accounts | Where-Object { $_.Rights -contains $right.Name } | ForEach-Object {$_.Sid} | Sort-Object -Unique)
                if (($right.Holders -join '|') -cne ($fromAccounts -join '|')) { $errors+='LSA holder and per-account observations differ; retry a consistent snapshot.' }
            }
        }
        try { $crash=Get-WelaRegistryState -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name CrashOnAuditFail }
        catch { $errors+="CrashOnAuditFail : $($_.Exception.Message)" }
    }
    [pscustomobject]@{Host=$hostState;Rights=$rights;Accounts=$accounts;CrashOnAuditFail=$crash;Errors=$errors}
}
function Get-WelaIntegrityProfiles {
    $catalog=Get-Content -LiteralPath (Join-Path $PSScriptRoot '../config/audit_integrity_profiles.json') -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($catalog.SchemaVersion -ne 1) { throw 'Unsupported integrity profile catalog.' }
    return @($catalog.Profiles)
}
function Get-WelaIntegrityStateKey {
    param($Snapshot)
    ConvertTo-Json -InputObject $Snapshot -Depth 14 -Compress
}
function Get-WelaIntegrityPrincipal {
    param([string]$Sid)
    $name=switch ($Sid) { 'S-1-5-19' {'LOCAL SERVICE'} 'S-1-5-20' {'NETWORK SERVICE'} 'S-1-5-32-544' {'BUILTIN\Administrators'} default {$null} }
    if (-not $name -and $env:OS -eq 'Windows_NT') { try { $name=([Security.Principal.SecurityIdentifier]::new($Sid)).Translate([Security.Principal.NTAccount]).Value } catch { } }
    [pscustomobject]@{Sid=$Sid;Name=$name;NameStatus=$(if ($name) {'Resolved'} else {'Unresolved; SID remains authoritative'})}
}
function Get-WelaIntegrityPlan {
    param($Snapshot,[string]$Profile,[switch]$AllowPrivilegeRemoval)
    $source=$null;$blockers=@($Snapshot.Errors);$operations=@();$rows=@()
    if ($Profile) {
        $matches=@(Get-WelaIntegrityProfiles | Where-Object Id -eq $Profile)
        if ($matches.Count -ne 1) { throw "Unknown audit integrity profile: $Profile" }
        $source=$matches[0]
        if ($Snapshot.Host.Status -ne 'Known' -or $source.Role -ne $Snapshot.Host.Role -or $Snapshot.Host.Build -lt $source.MinBuild -or $Snapshot.Host.Build -gt $source.MaxBuild) { $blockers+='Selected source profile does not match the actual Windows role/build.' }
    }
    foreach ($right in @('SeAuditPrivilege','SeSecurityPrivilege')) {
        $observed=@($Snapshot.Rights | Where-Object Name -eq $right)
        $current=@(if ($observed.Count -eq 1) { $observed[0].Holders })
        $desired=$null; if ($source -and $null -ne $source.$right) { $desired=@($source.$right | Sort-Object -Unique) }
        $adds=@();$removes=@();$mode='Preserve'
        if ($null -ne $desired) {
            $mode='Exact';$adds=@($desired | Where-Object { $current -notcontains $_ });$removes=@($current | Where-Object { $desired -notcontains $_ })
            if ($removes.Count -and -not $AllowPrivilegeRemoval) { $blockers+="$right has extra principals; inspect service/dependency exceptions and explicitly use -AllowPrivilegeRemoval before revoking them." }
            foreach ($sid in $adds) { $operations+=[pscustomobject]@{Kind='Right';Right=$right;Sid=$sid;Grant=$true} }
            foreach ($sid in $removes) { $operations+=[pscustomobject]@{Kind='Right';Right=$right;Sid=$sid;Grant=$false} }
        }
        $rows+=[pscustomobject]@{Name=$right;Mode=$mode;SourceSetting=$(if (-not $source) {'NoSourceSelected'} elseif ($null -eq $desired) {'OmittedBySource'} else {'ExplicitRequirement'});ObservedStatus=$(if ($observed.Count) {$observed[0].Status} else {'Unknown'});Current=$current;Desired=$desired;Add=@($adds|ForEach-Object {Get-WelaIntegrityPrincipal $_});Remove=@($removes|ForEach-Object {Get-WelaIntegrityPrincipal $_})}
    }
    $crash=$Snapshot.CrashOnAuditFail;$crashStatus='Unknown'
    if ($crash -and $crash.KeyExists) {
        if (-not $crash.ValueExists) { $crashStatus='Absent; no explicit value observed' }
        elseif ($crash.Type -eq 'DWord' -and $crash.Value -in @(0,1)) { $crashStatus=if ($crash.Value -eq 0) {'Disabled'} else {'Enabled'} }
        elseif ($crash.Type -eq 'DWord' -and $crash.Value -eq 2) { $crashStatus='RecoveryRequired';$blockers+='CrashOnAuditFail=2 is a recovery state. This workflow never resets it or clears the Security log.' }
        else { $blockers+='Unknown CrashOnAuditFail type/value; preserve it for manual review.' }
    } else { $blockers+='LSA registry key/state could not be verified.' }
    $crashMode='Preserve';$crashDesired=$null
    if ($source -and $null -ne $source.CrashOnAuditFail) {
        if ($source.CrashOnAuditFail -ne 0) { throw 'Only reviewed disabled CrashOnAuditFail profiles are supported.' }
        $crashMode='Exact';$crashDesired=0
        if ($crashStatus -ne 'Disabled') { $operations+=[pscustomobject]@{Kind='Registry';Name='CrashOnAuditFail';Desired=0} }
    }
    $rows+=[pscustomobject]@{Name='CrashOnAuditFail';Mode=$crashMode;SourceSetting=$(if (-not $source) {'NoSourceSelected'} elseif ($null -eq $crashDesired) {'OmittedBySource'} else {'ExplicitRequirement'});ObservedStatus=$crashStatus;Current=$crash;Desired=$crashDesired;Add=@();Remove=@()}
    [pscustomobject]@{Profile=$source;Before=$Snapshot;Controls=$rows;Operations=$operations;Blockers=@($blockers|Select-Object -Unique);AllowPrivilegeRemoval=[bool]$AllowPrivilegeRemoval;
        Exceptions=@('IIS application pools can require SeAuditPrivilege.','AD FS service identities can require SeAuditPrivilege.','Exchange Servers can require SeSecurityPrivilege on DCs.','Other application dependencies must be reviewed before any removal.');
        VerificationScope='Local LSA direct assignments and typed registry readback only. Existing tokens, GPO persistence, benign event generation, ingestion and effective user/group access are not verified.'}
}
function Copy-WelaIntegrityExpected {
    param($Snapshot)
    Get-WelaIntegrityStateKey $Snapshot | ConvertFrom-Json
}
function Update-WelaIntegrityExpected {
    param($Snapshot,$Operation)
    if ($Operation.Kind -eq 'Registry') {
        $Snapshot.CrashOnAuditFail.ValueExists=$true;$Snapshot.CrashOnAuditFail.Value=0;$Snapshot.CrashOnAuditFail.Type='DWord'
    } else {
        $right=@($Snapshot.Rights|Where-Object Name -eq $Operation.Right)[0]
        $account=@($Snapshot.Accounts|Where-Object Sid -eq $Operation.Sid)[0]
        if (-not $right -or -not $account) { throw 'Missing affected principal in the recovery snapshot.' }
        if ($Operation.Grant) { $right.Holders=@(@($right.Holders)+$Operation.Sid|Sort-Object -Unique);$account.Rights=@(@($account.Rights)+$Operation.Right|Sort-Object -Unique) }
        else { $right.Holders=@($right.Holders|Where-Object {$_ -ne $Operation.Sid});$account.Rights=@($account.Rights|Where-Object {$_ -ne $Operation.Right}) }
    }
}
function Set-WelaIntegrityControls {
    param($Context,$Plan)
    $expected=Copy-WelaIntegrityExpected $Plan.Before
    foreach ($operation in $Plan.Operations) { Update-WelaIntegrityExpected $expected $operation }
    $state=@{Plan=$Plan;Expected=$expected;ObserveSids=@($Plan.Before.Accounts.Sid)}
    $read={param($s) Get-WelaIntegritySnapshot -ObserveSids $s.ObserveSids}
    $test={param($snapshot,$s) -not $s.Plan.Blockers.Count -and (Get-WelaIntegrityStateKey $snapshot) -ceq (Get-WelaIntegrityStateKey $s.Expected)}
    $apply={
        param($s)
        if ($s.Plan.Blockers.Count) { throw ($s.Plan.Blockers -join ' ') }
        $expected=Copy-WelaIntegrityExpected $s.Plan.Before
        if ((Get-WelaIntegrityStateKey (Get-WelaIntegritySnapshot -ObserveSids $s.ObserveSids)) -cne (Get-WelaIntegrityStateKey $expected)) { throw 'Audit-integrity state changed since planning; no write was sent.' }
        foreach ($operation in $s.Plan.Operations) {
            $fresh=Get-WelaIntegritySnapshot -ObserveSids $s.ObserveSids
            if ((Get-WelaIntegrityStateKey $fresh) -cne (Get-WelaIntegrityStateKey $expected)) { throw 'Audit-integrity state changed before the next write; remaining operations stopped.' }
            if ($operation.Kind -eq 'Right') { Set-WelaIntegrityAccountRight -Sid $operation.Sid -Right $operation.Right -Grant $operation.Grant }
            else { Set-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name CrashOnAuditFail -Value 0 -Type DWord -ErrorAction Stop }
            Update-WelaIntegrityExpected $expected $operation
            $after=Get-WelaIntegritySnapshot -ObserveSids $s.ObserveSids
            if ((Get-WelaIntegrityStateKey $after) -cne (Get-WelaIntegrityStateKey $expected)) { throw 'Audit-integrity write/readback or unrelated-right preservation did not verify; remaining operations stopped. Review the recovery journal.' }
        }
    }
    Invoke-WelaConfigurationControl -Context $Context -Id 'AuditIntegrity/LocalPolicy' -Kind 'AuditIntegritySet' -Target @('SeAuditPrivilege','SeSecurityPrivilege','CrashOnAuditFail') -Desired $Plan `
        -Read $read -Compliant $test -Apply $apply -CallbackState $state -Description 'Apply the exact listed local privilege additions/removals and selected CrashOnAuditFail policy. Review every affected SID and service exception first.'
}
function Invoke-WelaIntegrityCommand {
    param([ValidateSet('Audit','Plan','Configure')][string]$Action='Audit',[string]$Profile,[switch]$AllowPrivilegeRemoval,[switch]$Auto,[switch]$DryRun,[string]$BackupPath,[string]$ResultsPath)
    if ($Action -ne 'Audit' -and -not $Profile) { throw 'Plan and Configure require an explicit -IntegrityProfile.' }
    if ($AllowPrivilegeRemoval -and (-not $Profile -or $Action -eq 'Audit')) { throw '-AllowPrivilegeRemoval requires an explicit profile with Plan or Configure.' }
    if ($DryRun -and $Action -ne 'Configure') { throw '-DryRun requires IntegrityAction Configure; Audit and Plan are read-only.' }
    $snapshot=Get-WelaIntegritySnapshot
    $plan=Get-WelaIntegrityPlan -Snapshot $snapshot -Profile $Profile -AllowPrivilegeRemoval:$AllowPrivilegeRemoval
    $report=[pscustomobject]@{Scope='audit-integrity-local-policy-only';ExitCode=$(if ($plan.Blockers.Count) {1} else {0});Action=$Action;Plan=$plan}
    # Show complete affected principals before the shared runner asks for consent.
    Write-Host "Observed host: $($snapshot.Host.ComputerName); role/build: $($snapshot.Host.Role)/$($snapshot.Host.Build); source profile: $Profile"
    Write-Host 'Plan observations (before any configuration):'
    foreach ($row in $plan.Controls) {
        Write-Host "$($row.Name): $($row.Mode); $($row.SourceSetting); $($row.ObservedStatus)"
        Write-Host ('  Current: ' + (ConvertTo-Json -InputObject $row.Current -Depth 4 -Compress))
        if ($row.Mode -eq 'Exact') { Write-Host ('  Requested: ' + (ConvertTo-Json -InputObject $row.Desired -Compress)) }
        foreach ($principal in $row.Add) { Write-Host "  ADD: $($principal.Sid) ($($principal.Name))" }
        foreach ($principal in $row.Remove) { Write-Host "  REMOVE: $($principal.Sid) ($($principal.Name))" }
    }
    if (@($plan.Controls.Remove).Count) { Write-Host ($plan.Exceptions -join ' ') }
    foreach ($blocker in $plan.Blockers) { Write-Host "Blocked: $blocker" -ForegroundColor Yellow }
    Write-Host $plan.VerificationScope
    if ($Action -eq 'Configure') {
        # Refuse unresolved scope/recovery/removal decisions even before creating a journal directory.
        if ($plan.Blockers.Count) { throw ($plan.Blockers -join ' ') }
        $context=New-WelaConfigurationContext -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath
        Set-WelaIntegrityControls -Context $context -Plan $plan
        $report=Complete-WelaConfiguration -Context $context -Scope 'audit-integrity-local-policy-only' -SuccessMessage 'Audit-integrity configuration completed. Applied/AlreadyCompliant rows verify local settings; skipped rows do not. Token, GPO and event evidence remain separate checks.'
        $report|Add-Member NoteProperty Action $Action
        $report|Add-Member NoteProperty Plan $plan
    }
    $report|Add-Member NoteProperty SigmaEvtxCredit 0
    if ($ResultsPath) { $report|ConvertTo-Json -Depth 18|Set-Content -LiteralPath $ResultsPath -Encoding UTF8 -ErrorAction Stop }
    return $report
}
