# Native CA auditing; production functions never provision a CA or submit requests.
function Get-WelaAdcsSource {
    param([string]$Profile='microsoft-identity-ca-2026-09')
    if ($Profile -cne 'microsoft-identity-ca-2026-09') { throw 'Unknown AD CS source profile. Use microsoft-identity-ca-2026-09.' }
    $path=Join-Path $PSScriptRoot '../config/audit_profiles.json'
    $before=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    $plan=Get-WelaAuditProfilePlan -Profile microsoft-identity-reviewed-2026-09 -Role ADCS -Build 20348
    $selected=@($plan.policies | Where-Object { $_.mode -in @('exact','minimum') })
    if ($selected.Count -ne 1 -or $selected[0].id -cne 'Certification Services' -or $selected[0].guid -ine '0cce9221-69ae-11d9-bed3-505054503030' -or $selected[0].mode -ne 'minimum' -or $selected[0].requiredMask -ne 3 -or
        $plan.schemaSha256.ToLowerInvariant() -cne $before -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $before) { throw 'Reviewed Certification Services source profile changed or is inconsistent.' }
    [pscustomobject]@{Id=$Profile;AdvancedProfile=$plan.profile;SchemaPath=$path;SchemaSha256=$before;AuditGuid=$selected[0].guid;AuditMask=3;AuditMode='minimum';Precedence=1;AuditFilter=127;SourceUrl='https://learn.microsoft.com/en-us/defender-for-identity/deploy/event-collection-overview';Reviewed='2026-09-20';Scope='Native CA audit settings only; no MDI sensor, template, AD-object or complete baseline configuration.'}
}
function Assert-WelaAdcsSource {
    param($Source)
    if ((Get-FileHash -LiteralPath $Source.SchemaPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() -cne $Source.SchemaSha256) { throw 'AD CS source profile changed after planning.' }
}
function ConvertTo-WelaAdcsThumbprints {
    param($Values)
    $items=@($Values)
    if($items.Count -lt 1){throw 'CA certificate hash list is empty.'}
    $seen=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach($value in $items){
        # Native CACertHash REG_MULTI_SZ uses twenty space-separated octets;
        # certificate-store thumbprints use the same forty hex digits unspaced.
        if($value -isnot [string] -or $value -notmatch '^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{2}(?: [0-9a-fA-F]{2}){19})$'){throw 'CA certificate hash list is malformed.'}
        $normalized=$value.Replace(' ','').ToUpperInvariant()
        if(-not $seen.Add($normalized)){throw 'CA certificate hash identity is duplicated.'}
        $normalized
    }
}
function Get-WelaAdcsCertificates {
    param([string[]]$Thumbprints)
    $store=New-Object Security.Cryptography.X509Certificates.X509Store('My','LocalMachine')
    $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor [Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)
    try {
        foreach ($thumbprint in $Thumbprints) {
            $certificates=@($store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,$thumbprint,$false))
            if ($certificates.Count -ne 1) { throw 'Configured CA certificate is absent or ambiguous in LocalMachine/My.' }
            $certificate=$certificates[0];$hash=[Security.Cryptography.SHA256]::Create()
            try { $sha=([BitConverter]::ToString($hash.ComputeHash($certificate.RawData))).Replace('-','').ToLowerInvariant() } finally { $hash.Dispose() }
            [pscustomobject]@{Thumbprint=$certificate.Thumbprint.ToUpperInvariant();Sha256=$sha;Subject=$certificate.Subject;SerialNumber=$certificate.SerialNumber}
        }
    } finally { $store.Close() }
}
function Get-WelaAdcsSnapshot {
    $result=[pscustomobject][ordered]@{Status='Unknown';Diagnostic='';CapturedUtc=[DateTime]::UtcNow.ToString('o');Host=$null;Active=$null;Path=$null;CaType=$null;CertificateHashes=$null;Certificates=@();Filter=$null;Service=$null;AuditMask=$null;Precedence=$null}
    try {
        if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess) { throw '64-bit Windows is required for native CA observation.' }
        $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        if ($os.ProductType -notin @(1,2,3) -or ($os.ProductType -eq 1 -and $computer.DomainRole -notin @(0,1)) -or ($os.ProductType -eq 2 -and $computer.DomainRole -notin @(4,5)) -or ($os.ProductType -eq 3 -and $computer.DomainRole -notin @(2,3)) -or $computer.PartOfDomain -isnot [bool]) { throw 'Windows role observations are incomplete or contradictory.' }
        $version=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        if ([string]$os.BuildNumber -notmatch '^\d+$' -or $null -eq $version.UBR -or -not $version.EditionID -or -not $computer.Name) { throw 'Exact Windows build/patch/edition/host identity is unavailable.' }
        $result.Host=[pscustomobject]@{Computer=[string]$computer.Name;DnsHostName=[string]$computer.DNSHostName;Build=[int]$os.BuildNumber;UBR=[int]$version.UBR;Edition=[string]$version.EditionID;ProductType=[int]$os.ProductType;DomainRole=[int]$computer.DomainRole;DomainJoined=[bool]$computer.PartOfDomain;Domain=[string]$computer.Domain}
        $root='HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
        if (-not (Test-Path -LiteralPath $root -ErrorAction Stop)) { $result.Status='NotApplicable';$result.Diagnostic='No configured local CA. No CA is installed by this command.';return $result }
        if ($os.ProductType -ne 3 -or $computer.DomainRole -notin @(2,3)) { throw 'Only a dedicated server CA is supported; client and combined DC/CA configuration are refused.' }
        if ($result.Host.Build -notin @(20348,26100)) { throw 'CA host build is outside the reviewed Server 2022/2025 families.' }
        $result.Active=Get-WelaRegistryState -Path $root -Name Active
        if (-not $result.Active.ValueExists -or $result.Active.Type -ne 'String' -or $result.Active.Value -isnot [string] -or [string]::IsNullOrWhiteSpace($result.Active.Value) -or $result.Active.Value -match '[\\/\x00-\x1f]' -or $result.Active.Value -in @('.','..')) { throw 'The active CA name must identify exactly one existing registry child.' }
        $result.Path=$root+'\'+$result.Active.Value
        $result.CaType=Get-WelaRegistryState -Path $result.Path -Name CAType
        if (-not $result.CaType.ValueExists -or $result.CaType.Type -ne 'DWord' -or $result.CaType.Value -notin @(0,1,3,4)) { throw 'CA type is missing or unsupported.' }
        $result.CertificateHashes=Get-WelaRegistryState -Path $result.Path -Name CACertHash
        if (-not $result.CertificateHashes.ValueExists -or $result.CertificateHashes.Type -ne 'MultiString') { throw 'CA certificate identity is unavailable.' }
        $hashes=@(ConvertTo-WelaAdcsThumbprints $result.CertificateHashes.Value)
        $result.Certificates=@(Get-WelaAdcsCertificates $hashes)
        $result.Filter=Get-WelaRegistryState -Path $result.Path -Name AuditFilter
        if (-not $result.Filter.KeyExists -or ($result.Filter.ValueExists -and ($result.Filter.Type -ne 'DWord' -or ($result.Filter.Value -isnot [int] -and $result.Filter.Value -isnot [long]) -or $result.Filter.Value -lt 0 -or $result.Filter.Value -gt 127))) { throw 'Unknown CA AuditFilter type/bits are preserved for manual review.' }
        $services=@(Get-CimInstance Win32_Service -Filter "Name='CertSvc'" -ErrorAction Stop)
        if ($services.Count -ne 1 -or $services[0].StartMode -notin @('Auto','Manual','Disabled') -or $services[0].State -notin @('Running','Stopped')) { throw 'Certificate Services state is absent or transitional.' }
        $service=$services[0];$start=$null
        if ($service.State -eq 'Running') {
            if (-not $service.ProcessId) { throw 'Running CA service has no process identity.' }
            $start=(Get-Process -Id $service.ProcessId -ErrorAction Stop).StartTime.ToUniversalTime().ToString('o')
        }
        $dependents=@((Get-Service -Name CertSvc -ErrorAction Stop).DependentServices | ForEach-Object { [pscustomobject]@{Name=[string]$_.Name;Status=[string]$_.Status} } | Sort-Object Name)
        $result.Service=[pscustomobject]@{Name='CertSvc';Status=[string]$service.State;StartMode=[string]$service.StartMode;ProcessId=[long]$service.ProcessId;StartUtc=$start;Dependents=$dependents}
        $result.AuditMask=Get-WelaAuditPolicyMask -Guid '0cce9221-69ae-11d9-bed3-505054503030'
        if (($result.AuditMask -isnot [int] -and $result.AuditMask -isnot [long]) -or $result.AuditMask -notin @(0,1,2,3)) { throw 'Effective Certification Services audit mask is unknown.' }
        $result.Precedence=Get-WelaRegistryState -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy
        if ($result.Precedence.ValueExists -and ($result.Precedence.Type -ne 'DWord' -or $result.Precedence.Value -notin @(0,1))) { throw 'Unknown audit precedence type/value is preserved.' }
        $result.Status='Supported';$result.Diagnostic='CA identity and current settings observed. Service activation of AuditFilter and event generation remain unverified.'
    } catch { $result.Diagnostic=$_.Exception.Message }
    return $result
}
function Get-WelaAdcsStateKey {
    param($State,[ValidateSet('None','Precedence','AuditMask','Filter','Restart')][string]$Omit='None')
    $service=$State.Service
    if ($Omit -eq 'Restart' -and $service) { $service=[ordered]@{Name=$service.Name;Status=$service.Status;StartMode=$service.StartMode;Dependents=@($service.Dependents)} }
    [ordered]@{Status=$State.Status;Host=$State.Host;Active=$State.Active;Path=$State.Path;CaType=$State.CaType;CertificateHashes=$State.CertificateHashes;Certificates=@($State.Certificates);Filter=$(if($Omit -ne 'Filter'){$State.Filter});Service=$service;AuditMask=$(if($Omit -ne 'AuditMask'){$State.AuditMask});Precedence=$(if($Omit -ne 'Precedence'){$State.Precedence})} | ConvertTo-Json -Depth 12 -Compress
}
function Test-WelaAdcsPrecedence {
    param($State)
    return $State.Precedence.ValueExists -and $State.Precedence.Type -eq 'DWord' -and $State.Precedence.Value -eq 1
}
function Assert-WelaAdcsPrerequisites {
    param($State)
    if ($State.Status -ne 'Supported') { throw "CA unavailable: $($State.Diagnostic)" }
    if (-not (Test-WelaAdcsPrecedence $State) -or $State.AuditMask -ne 3) { throw 'Effective Certification Services Success+Failure and typed audit precedence are required before CA changes.' }
    if ($State.Service.Status -ne 'Running' -or $State.Service.StartMode -eq 'Disabled') { throw 'CertSvc must already be running; WELA never starts a stopped or disabled CA.' }
}
function Test-WelaAdcsControl {
    param($Snapshot,[string]$Control)
    switch ($Control) {
        'Precedence' { return (Test-WelaAdcsPrecedence $Snapshot) }
        'AuditMask' { return $Snapshot.AuditMask -eq 3 }
        'Filter' { return $Snapshot.Filter.ValueExists -and $Snapshot.Filter.Type -eq 'DWord' -and $Snapshot.Filter.Value -eq 127 }
    }
}
function Restart-WelaAdcsService {
    # No Force: dependent services must not be stopped implicitly.
    Restart-Service -Name CertSvc -ErrorAction Stop
    (Get-Service -Name CertSvc -ErrorAction Stop).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(30))
}
function Set-WelaAdcsControls {
    param($Context,$Source,$Snapshot,[switch]$ConfigurePrerequisites,[switch]$AllowRestart)
    $shared=@{Expected=$Snapshot;Source=$Source;Activation='Unverified';Blocked=$false;AllowRestart=[bool]$AllowRestart}
    $definitions=@()
    if ($ConfigurePrerequisites) { $definitions+=@('Precedence','AuditMask') }
    $definitions+='Filter'
    $filterChange=-not (Test-WelaAdcsControl $Snapshot Filter)
    $failure=$null
    try {
        Assert-WelaAdcsSource $Source
        if ($Snapshot.Status -ne 'Supported') { throw "CA unavailable: $($Snapshot.Diagnostic)" }
        if ($Snapshot.Service.Status -ne 'Running' -or $Snapshot.Service.StartMode -eq 'Disabled') { throw 'CertSvc must already be running; no stopped CA is started.' }
        if (-not $ConfigurePrerequisites) {
            if (-not $Context.DryRun) { Assert-WelaAdcsPrerequisites $Snapshot }
            if (@($Context.Results | Where-Object { ($_.Id -eq 'AuditPolicy/Certification Services' -or $_.Id -like '*SCENoApplyLegacyAuditPolicy') -and $_.Status -notin @('Applied','AlreadyCompliant') -and -not ($Context.DryRun -and $_.Status -eq 'Skipped' -and $_.Diagnostic -like 'Dry run:*') }).Count) { throw 'Earlier audit prerequisite control was not verified; CA changes are blocked.' }
        }
        if ($filterChange -and -not $AllowRestart -and -not $Context.DryRun) { throw 'An AuditFilter change requires explicit -AllowRestart on the dedicated command; no settings were changed.' }
        if ($filterChange -and @($Snapshot.Service.Dependents | Where-Object Status -ne 'Stopped').Count) { throw 'Running dependent services prevent an isolated CertSvc restart; no settings were changed.' }
    } catch { $failure=$_.Exception.Message }
    if ($failure) {
        $Context.Results.Add([pscustomobject]@{Id='ADCS/Prerequisites';Kind='AdcsAudit';Target=$Snapshot.Path;Desired=$Source;Before=$Snapshot;After=$null;Status='Failed';Diagnostic=$failure})
        return [pscustomobject]@{Activation='Unverified';State=$Snapshot}
    }
    foreach ($control in $definitions) {
        if ($shared.Blocked) { $Context.Results.Add([pscustomobject]@{Id="ADCS/$control";Kind='AdcsAudit';Target=$Snapshot.Path;Desired=$control;Before=$null;After=$null;Status='Skipped';Diagnostic='A prior CA/audit control failed or was declined.'});continue }
        $state=@{Shared=$shared;Control=$control}
        $read={ param($state)
            Assert-WelaAdcsSource $state.Shared.Source
            $current=Get-WelaAdcsSnapshot
            if ($current.Status -ne 'Supported' -or (Get-WelaAdcsStateKey $current) -cne (Get-WelaAdcsStateKey $state.Shared.Expected)) { throw "CA identity, certificate, filter, service or audit state changed: $($current.Diagnostic)" }
            return $current
        }
        $test={ param($current,$state) Test-WelaAdcsControl $current $state.Control }
        $apply={ param($state)
            Assert-WelaAdcsSource $state.Shared.Source
            $fresh=Get-WelaAdcsSnapshot
            if ($fresh.Status -ne 'Supported' -or (Get-WelaAdcsStateKey $fresh) -cne (Get-WelaAdcsStateKey $state.Shared.Expected)) { throw 'CA state changed after journaling; write refused.' }
            if ($state.Control -eq 'AuditMask' -and -not (Test-WelaAdcsPrecedence $fresh)) { throw 'Audit precedence was not verified.' }
            if ($state.Control -eq 'Filter') { Assert-WelaAdcsPrerequisites $fresh }
            switch ($state.Control) {
                'Precedence' { Set-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy -Value 1 -Type DWord -ErrorAction Stop }
                'AuditMask' { Set-WelaEffectiveAuditPolicy -Guid $state.Shared.Source.AuditGuid -Mask 3 -Mode minimum }
                'Filter' { Set-ItemProperty -LiteralPath $fresh.Path -Name AuditFilter -Value 127 -Type DWord -ErrorAction Stop }
            }
            $after=Get-WelaAdcsSnapshot
            if ($after.Status -ne 'Supported' -or (Get-WelaAdcsStateKey $fresh $state.Control) -cne (Get-WelaAdcsStateKey $after $state.Control) -or -not (Test-WelaAdcsControl $after $state.Control)) { throw 'CA control readback or preservation check failed; inspect the journal.' }
            $state.Shared.Expected=$after
            if ($state.Control -eq 'Filter') {
                $state.Shared.Activation='RestartPending'
                Assert-WelaAdcsSource $state.Shared.Source
                $ready=Get-WelaAdcsSnapshot;Assert-WelaAdcsPrerequisites $ready
                if ((Get-WelaAdcsStateKey $ready) -cne (Get-WelaAdcsStateKey $after)) { throw 'CA state changed before restart; service was not restarted.' }
                if (-not $state.Shared.AllowRestart) { throw 'Restart was not authorized.' }
                Restart-WelaAdcsService
                $restarted=Get-WelaAdcsSnapshot;Assert-WelaAdcsPrerequisites $restarted
                if ((Get-WelaAdcsStateKey $ready Restart) -cne (Get-WelaAdcsStateKey $restarted Restart) -or $ready.Service.StartUtc -ceq $restarted.Service.StartUtc -or [DateTime]$restarted.Service.StartUtc -le [DateTime]$ready.Service.StartUtc) { throw 'CA restart/readback or preservation could not be verified.' }
                $state.Shared.Expected=$restarted;$state.Shared.Activation='RestartObservedAfterWrite; event generation unverified'
            }
        }
        $target=if ($control -eq 'Filter') { [ordered]@{Path=$Snapshot.Path;Name='AuditFilter';Service='CertSvc';ActiveCa=$Snapshot.Active.Value;Certificates=$Snapshot.Certificates} } elseif ($control -eq 'AuditMask') { @{Guid=$Source.AuditGuid} } else { @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';Name='SCENoApplyLegacyAuditPolicy'} }
        $desired=if($control -eq 'Filter'){@{Value=127;Type='DWord';RestartIfChanged=[bool]$AllowRestart}} elseif($control -eq 'AuditMask'){@{Mask=3;Mode='minimum'}} else {@{Value=1;Type='DWord'}}
        Invoke-WelaConfigurationControl -Context $Context -Id "ADCS/$control" -Kind AdcsAudit -Target $target -Desired $desired -Read $read -Compliant $test -Apply $apply -CallbackState $state -Description $(if($control -eq 'Filter'){'Set the reviewed CA AuditFilter and restart this running Certificate Services instance.'}else{'Apply the source-required audit prerequisite.'})
        $row=$Context.Results[$Context.Results.Count-1]
        $row | Add-Member NoteProperty Source $Source
        $row | Add-Member NoteProperty VerificationScope 'Current settings and preservation only; registry 127 and Running do not establish service activation or events.'
        if ($row.Status -eq 'Failed' -or ($row.Status -eq 'Skipped' -and -not $Context.DryRun)) { $shared.Blocked=$true }
    }
    return [pscustomobject]@{Activation=$shared.Activation;State=$shared.Expected}
}
function Invoke-WelaLegacyAdcsControl {
    param($Context)
    try {
        $snapshot=Get-WelaAdcsSnapshot
        if ($snapshot.Status -eq 'NotApplicable') { $Context.Results.Add([pscustomobject]@{Id='ADCS/AuditFilter';Kind='AdcsAudit';Target=$null;Desired=127;Before=$snapshot;After=$snapshot;Status='Skipped';Diagnostic=$snapshot.Diagnostic});return }
        $source=Get-WelaAdcsSource
        $outcome=Set-WelaAdcsControls -Context $Context -Source $source -Snapshot $snapshot -AllowRestart
        foreach ($row in @($Context.Results | Where-Object { $_.Kind -eq 'AdcsAudit' })) { $row | Add-Member NoteProperty Activation $outcome.Activation -Force }
    } catch { $Context.Results.Add([pscustomobject]@{Id='ADCS/AuditFilter';Kind='AdcsAudit';Target=$null;Desired=127;Before=$snapshot;After=$null;Status='Failed';Diagnostic=$_.Exception.Message}) }
}
function Get-WelaAdcsReportPath {
    param([string]$Path)
    $provider=$null;$drive=$null
    $full=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path,[ref]$provider,[ref]$drive)
    if ($provider.Name -ne 'FileSystem' -or $full -match '^[\\/]{2}' -or (Test-Path -LiteralPath $full -ErrorAction Stop)) { throw 'AD CS reports require a new local filesystem file.' }
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT -and ([IO.DriveInfo]::new([IO.Path]::GetPathRoot($full))).DriveType -ne [IO.DriveType]::Fixed) { throw 'AD CS evidence requires a local fixed drive.' }
    $parent=[IO.DirectoryInfo]([IO.Path]::GetDirectoryName($full))
    if (-not $parent.Exists) { throw 'AD CS report parent must exist.' }
    while($parent){if($parent.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'AD CS output cannot traverse a reparse-point directory.'};$parent=$parent.Parent}
    return $full
}
function Protect-WelaAdcsDirectory {
    param([string]$Path)
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return }
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    foreach($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')|Select-Object -Unique){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}
function Invoke-WelaAdcsCommand {
    param([ValidateSet('Audit','Plan','Configure')][string]$Action='Audit',[string]$Profile,[switch]$AllowRestart,[switch]$Auto,[switch]$DryRun,[string]$BackupPath,[string]$ResultsPath)
    if ($Action -ne 'Audit' -and -not $Profile) { throw 'AD CS Plan/Configure requires explicit -AdcsProfile microsoft-identity-ca-2026-09.' }
    if ($Action -ne 'Configure' -and ($AllowRestart -or $Auto -or $DryRun -or $BackupPath)) { throw 'Restart, consent, dry-run and backup options require AD CS Configure.' }
    if (-not $Profile) {$Profile='microsoft-identity-ca-2026-09'}
    $source=Get-WelaAdcsSource $Profile
    if($ResultsPath){$ResultsPath=Get-WelaAdcsReportPath $ResultsPath}
    $before=Get-WelaAdcsSnapshot
    $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaAdcsAuditing';Action=$Action;Source=$source;Before=$before;After=$before;ExitCode=$(if($before.Status -eq 'Unknown'){1}else{0});Results=@();Activation='Unverified';EventGeneration='Unverified';UsableRuleCredit=0;Scope='Native local CA auditing only. Sysmon, enrollment/template permissions, AD objects, leaf issuance and forwarding excluded.'}
    $report | Add-Member NoteProperty Plan @(
        foreach($control in @('Precedence','AuditMask','Filter')) {
            $current=switch($control){'Precedence'{$before.Precedence}'AuditMask'{$before.AuditMask}'Filter'{$before.Filter}}
            [pscustomobject]@{Control=$control;Current=$current;Desired=$(if($control -eq 'Filter'){'DWORD127, restart after change'}elseif($control -eq 'AuditMask'){'Success+Failure, minimum3'}else{'DWORD1'});State=$(if($before.Status -ne 'Supported'){$before.Status}elseif(Test-WelaAdcsControl $before $control){'PolicyMatches'}else{'ChangeRequired'})}
        }
    )
    if($Action -eq 'Configure' -and $before.Status -ne 'NotApplicable'){
        if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT){
            $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
            try{if(-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevated administrator rights are required for CA configuration.'}}finally{$identity.Dispose()}
        }

        if(-not $DryRun){
            if(-not $BackupPath){$BackupPath=Join-Path $script:ScriptRoot ('wela-adcs-backup-'+[guid]::NewGuid().ToString('N'))}
            $BackupPath=Get-WelaAdcsReportPath $BackupPath
        }
        $context=New-WelaConfigurationContext -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath
        if(-not $DryRun){Protect-WelaAdcsDirectory $context.BackupPath}
        $outcome=Set-WelaAdcsControls -Context $context -Source $source -Snapshot $before -ConfigurePrerequisites -AllowRestart:$AllowRestart
        $completed=Complete-WelaConfiguration -Context $context -Scope adcs-audit-settings-only -SuccessMessage 'CA settings verified. Activation and event evidence are reported separately.'
        $report.Results=$completed.Results;$report.ExitCode=$completed.ExitCode;$report.Activation=$outcome.Activation
        $report | Add-Member NoteProperty Configuration $completed
        $report.After=Get-WelaAdcsSnapshot
        if($report.After.Status -ne 'Supported' -or (Get-WelaAdcsStateKey $report.After) -cne (Get-WelaAdcsStateKey $outcome.State)){$report.ExitCode=1;$report.Activation='Unverified: final CA state changed'}
    }
    $report | Add-Member NoteProperty PolicyState $(if($report.After.Status -ne 'Supported'){$report.After.Status}elseif((Test-WelaAdcsControl $report.After Filter) -and (Test-WelaAdcsPrecedence $report.After) -and $report.After.AuditMask -eq 3){'PolicyMatches'}else{'ChangeRequired'})
    if($ResultsPath){$full=Get-WelaAdcsReportPath $ResultsPath;$bytes=([Text.UTF8Encoding]::new($false)).GetBytes(($report|ConvertTo-Json -Depth 22));$stream=[IO.File]::Open($full,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}}
    return $report
}

# Validate only components of a pending-request event. This is not Sigma/backend
# evidence and never submits, approves, retrieves or installs a certificate.
function Test-WelaAdcsRequestEvent {
    param([string]$Xml,$Expected,[ValidateSet(4886,4889)][int]$EventId)
    try {
        $settings=New-Object Xml.XmlReaderSettings;$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null
        $reader=[Xml.XmlReader]::Create((New-Object IO.StringReader($Xml)),$settings)
        try{$doc=New-Object Xml.XmlDocument;$doc.XmlResolver=$null;$doc.Load($reader)}finally{$reader.Dispose()}
        $ns=New-Object Xml.XmlNamespaceManager($doc.NameTable);$ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
        $system=$doc.SelectSingleNode('/e:Event/e:System',$ns)
        if(-not $system){return $false}
        $provider=$system.SelectSingleNode('e:Provider',$ns)
        if($provider.GetAttribute('Name') -cne 'Microsoft-Windows-Security-Auditing' -or [guid]$provider.GetAttribute('Guid') -ne [guid]'54849625-5478-4994-a5ba-3e3b0328c30d' -or
            $system.SelectSingleNode('e:EventID',$ns).InnerText -cne [string]$EventId -or $system.SelectSingleNode('e:Version',$ns).InnerText -cne '0' -or $system.SelectSingleNode('e:Channel',$ns).InnerText -cne 'Security' -or
            $system.SelectSingleNode('e:Computer',$ns).InnerText -ine $Expected.Computer -or $system.SelectSingleNode('e:Keywords',$ns).InnerText -ine '0x8020000000000000'){return $false}
        $utc=[DateTimeOffset]::Parse($system.SelectSingleNode('e:TimeCreated',$ns).GetAttribute('SystemTime'),[Globalization.CultureInfo]::InvariantCulture).UtcDateTime
        if($utc -lt ([DateTime]$Expected.StartUtc).ToUniversalTime() -or $utc -gt ([DateTime]$Expected.EndUtc).ToUniversalTime()){return $false}
        $data=New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
        foreach($node in @($doc.SelectNodes('/e:Event/e:EventData/e:Data',$ns))){$name=$node.GetAttribute('Name');if(-not $name -or $data.ContainsKey($name)){return $false};$data.Add($name,$node.InnerText)}
        if(-not $data.ContainsKey('RequestId') -or $data['RequestId'] -cne [string]$Expected.RequestId -or -not $data.ContainsKey('Requester') -or $data['Requester'] -ine $Expected.Requester -or -not $data.ContainsKey('Attributes')){return $false}
        # Retain and match the random request attribute without localized message parsing.
        return @($data['Attributes'] -split '\r?\n' | Where-Object { $_.Trim() -ceq ('WELAProbe:'+$Expected.Nonce) }).Count -eq 1
    }catch{return $false}
}
