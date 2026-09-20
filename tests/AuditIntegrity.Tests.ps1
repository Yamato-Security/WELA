$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/AuditIntegrity.ps1')
$script:ScriptRoot=$repo;$script:checks=0
function Assert($Value,[string]$Message) { if (-not $Value) { throw "FAIL: $Message" };$script:checks++ }
function Reject([scriptblock]$Code,[string]$Pattern) { $message='';try { & $Code|Out-Null } catch {$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern, got $message" }
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-integrity-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
function Reset-Fixture {
    $script:hostState=[pscustomobject]@{Status='Known';ComputerName='fixture';Role='Client';Build=26100;DomainJoined=$false;DomainRole=0;CertificateAuthority='NotInstalled'}
    $script:rights=@{'S-1-5-19'=@('SeAuditPrivilege','SeChangeNotifyPrivilege');'S-1-5-20'=@('SeAuditPrivilege','SeChangeNotifyPrivilege');'S-1-5-32-544'=@('SeSecurityPrivilege','SeBackupPrivilege')}
    $script:crash=[pscustomobject]@{KeyExists=$true;ValueExists=$true;Type='DWord';Value=0}
    $script:writes=@();$script:reads=0;$script:raceAt=0;$script:deny='';$script:ignore=$false;$script:corrupt=$false;$script:failAt=0
    $script:backup=Join-Path $temp ([guid]::NewGuid().ToString('N'))
}
function Get-WelaIntegrityHost { $script:reads++;if ($script:raceAt -eq $script:reads) {$script:rights['S-1-5-19']+=@('SeImpersonatePrivilege')};if($script:deny -eq 'Host'){throw 'host denied'};$script:hostState.PSObject.Copy() }
function Get-WelaIntegrityHolders { param($Right) if($script:deny -eq 'Holders'){throw 'LSA enumerate denied'};return ,@($script:rights.Keys|Where-Object {$script:rights[$_] -contains $Right}|Sort-Object) }
function Get-WelaIntegrityAccountRights { param($Sid) if($script:deny -eq 'Accounts'){throw 'account rights denied'};return ,@($script:rights[$Sid]) }
function Get-WelaRegistryState { param($Path,$Name) Assert ($Path -eq 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -and $Name -eq 'CrashOnAuditFail') 'Only the exact integrity registry value is observed';if($script:deny -eq 'Registry'){throw 'registry denied'};$script:crash.PSObject.Copy() }
function Record-Write($Operation) {
    Assert (Test-Path (Join-Path $script:backup 'before.jsonl')) 'Every mutation must follow a durable complete journal'
    $script:writes+=@($Operation)
    if($script:failAt -eq $script:writes.Count){throw 'native write denied'}
}
function Set-WelaIntegrityAccountRight {
    param($Sid,$Right,[bool]$Grant)
    Record-Write ([pscustomobject]@{Sid=$Sid;Right=$Right;Grant=$Grant})
    if($script:ignore){return}
    if($Grant){$script:rights[$Sid]=@(@($script:rights[$Sid])+$Right|Sort-Object -Unique)}else{$script:rights[$Sid]=@($script:rights[$Sid]|Where-Object {$_ -ne $Right})}
    if($script:corrupt){$script:rights[$Sid]=@($script:rights[$Sid]|Where-Object {$_ -ne 'SeBackupPrivilege'})}
}
function Set-ItemProperty { param($LiteralPath,$Name,$Value,$Type,$ErrorAction) Assert ($LiteralPath -eq 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -and $Name -eq 'CrashOnAuditFail' -and $Value -eq 0 -and $Type -eq 'DWord') 'Only disabled typed CrashOnAuditFail is written';Record-Write @{Name=$Name};if(-not $script:ignore){$script:crash.ValueExists=$true;$script:crash.Type='DWord';$script:crash.Value=0} }
function New-Context([switch]$DryRun) {New-WelaConfigurationContext -Auto -DryRun:$DryRun -BackupPath $script:backup}
function Plan([string]$Profile='cis-win11-v4-l1',[switch]$AllowRemoval) {Get-WelaIntegrityPlan (Get-WelaIntegritySnapshot) $Profile -AllowPrivilegeRemoval:$AllowRemoval}
function Configure([switch]$AllowRemoval,[switch]$DryRun) {Invoke-WelaIntegrityCommand -Action Configure -Profile cis-win11-v4-l1 -AllowPrivilegeRemoval:$AllowRemoval -Auto -DryRun:$DryRun -BackupPath $script:backup}
try {
    Reset-Fixture
    $profiles=@(Get-WelaIntegrityProfiles)
    Assert ($profiles.Count -eq 9) 'Explicit client/member/DC CIS and SCT source profiles are present'
    foreach($p in $profiles) {
        if($p.Id -like 'cis-*'){Assert (($p.SeAuditPrivilege -join ',') -eq 'S-1-5-19,S-1-5-20' -and ($p.SeSecurityPrivilege -join ',') -eq 'S-1-5-32-544' -and $p.CrashOnAuditFail -eq 0) 'CIS exact principal sets and disabled crash policy match reviewed source'}
        else {Assert ($null -eq $p.SeAuditPrivilege -and $null -eq $p.CrashOnAuditFail -and $p.TemplateSha256 -match '^[a-f0-9]{64}$') 'SCT omission is preserved and template bytes are identified'}
    }
    Assert ($null -eq ($profiles|Where-Object Id -eq 'microsoft-sct-server2025-v2602-dc').SeSecurityPrivilege) 'Server 2025 v2602 DC template omission is not filled from the member template'
    $report=Invoke-WelaIntegrityCommand
    Assert ($report.SigmaEvtxCredit -eq 0 -and $report.ExitCode -eq 0 -and $script:writes.Count -eq 0 -and -not(Test-Path $backup)) 'Default audit creates no journal and performs no writes'
    Reject {Invoke-WelaIntegrityCommand -Action Configure} 'explicit'
    Reject {Invoke-WelaIntegrityCommand -Action Plan} 'explicit'
    Reject {Invoke-WelaIntegrityCommand -DryRun} 'DryRun'
    Reject {Get-WelaIntegrityPlan (Get-WelaIntegritySnapshot) typo} 'Unknown'
    $report=Configure
    Assert ($report.Results[0].Status -eq 'AlreadyCompliant' -and $script:writes.Count -eq 0) 'Matching assignments and DWORD are idempotent'
    Reset-Fixture;$script:rights['S-1-5-20']=@('SeChangeNotifyPrivilege');$script:crash.Value=1
    $report=Configure -DryRun
    Assert ($report.ExitCode -eq 0 -and $script:writes.Count -eq 0 -and -not(Test-Path $backup)) 'Dry-run never calls setters or writes recovery files'
    $report=Configure
    Assert ($report.ExitCode -eq 0 -and $script:writes.Count -eq 2 -and $script:rights['S-1-5-20'] -contains 'SeChangeNotifyPrivilege') 'Only missing right and selected crash policy change; unrelated privileges survive'
    $journal=Get-Content (Join-Path $backup 'before.jsonl') -Raw|ConvertFrom-Json
    Assert ($journal.Before.Accounts.Count -eq 3 -and $journal.Before.CrashOnAuditFail.Value -eq 1 -and $journal.Before.Accounts[0].Rights.Count -gt 0) 'Journal retains all affected accounts full rights and exact prior DWORD'
    Reset-Fixture;$script:rights['S-1-5-21-1-2-3-1001']=@('SeSecurityPrivilege','SeBackupPrivilege')
    $plan=Plan
    Assert ($plan.Blockers.Count -gt 0 -and $plan.Controls[1].Remove[0].Sid -eq 'S-1-5-21-1-2-3-1001') 'Exact extra SID is enumerated and removal requires explicit consent'
    Reject {Configure} 'AllowPrivilegeRemoval'
    Assert ($script:writes.Count -eq 0 -and -not(Test-Path $backup)) 'Unapproved removal blocks all mutations before journal creation'
    $report=Configure -AllowRemoval
    Assert ($report.ExitCode -eq 0 -and $script:rights['S-1-5-21-1-2-3-1001'] -notcontains 'SeSecurityPrivilege' -and $script:rights['S-1-5-21-1-2-3-1001'] -contains 'SeBackupPrivilege') 'Explicit per-right removal preserves all other account rights'
    Reset-Fixture;$script:rights['S-1-5-21-1-2-3-1001']=@('SeSecurityPrivilege','SeBackupPrivilege')
    $script:messages=@()
    & {
        function Write-Host {param($Object,$ForegroundColor) $script:messages+=@([string]$Object)}
        function Read-Host {param($Prompt)
            Assert (($script:messages -join '|') -match 'REMOVE: S-1-5-21-1-2-3-1001' -and $script:writes.Count -eq 0) 'Complete affected SID is printed before the consent prompt or any write'
            'n'
        }
        $declined=Invoke-WelaIntegrityCommand -Action Configure -Profile cis-win11-v4-l1 -AllowPrivilegeRemoval -BackupPath $script:backup
        Assert ($declined.Results[0].Status -eq 'Skipped' -and $script:writes.Count -eq 0) 'Declining the reviewed plan preserves all privileges'
    }
    Reset-Fixture;$script:hostState.Role='DomainController';$script:hostState.Build=20348;$script:hostState.DomainJoined=$true;$script:hostState.DomainRole=5
    Assert ((Plan cis-server2022-v4-dc).Blockers.Count -eq 0) 'DC source is selected only against an observed DC'
    Assert ((Plan cis-server2022-v4-member).Blockers.Count -gt 0) 'A member profile cannot mutate DC assignments'
    $script:hostState.Role='MemberServer';$script:hostState.DomainRole=3;$script:hostState.CertificateAuthority='Installed'
    Assert ((Plan cis-server2022-v4-member).Blockers.Count -eq 0) 'A member-server CA remains a member profile with separate CA evidence'
    $script:hostState.Build=26100
    Assert ((Plan cis-server2022-v4-member).Blockers.Count -gt 0) 'Server 2022 CIS profiles are not silently applied to Server 2025'
    Reset-Fixture;$script:crash.Value=1;$script:rights['S-1-5-19']=@('SeChangeNotifyPrivilege')
    $plan=Plan microsoft-sct-win11-24h2
    Assert ($plan.Operations.Count -eq 0 -and $plan.Controls[0].SourceSetting -eq 'OmittedBySource' -and $plan.Controls[2].Mode -eq 'Preserve') 'SCT omission does not synthesize Microsoft general/default recommendations'
    $context=New-Context;Set-WelaIntegrityControls $context $plan;$report=Complete-WelaConfiguration $context
    Assert ($report.ExitCode -eq 0 -and $script:crash.Value -eq 1 -and $script:writes.Count -eq 0) 'Omitted source controls remain byte-for-byte observed values'
    foreach($case in @('recovery','type','unknown','host','holders','accounts','registry','plan-race','prewrite-race','ignored','partial','corrupt','final-drift','preserved-drift')) {
        Reset-Fixture;$script:rights['S-1-5-20']=@('SeChangeNotifyPrivilege');$script:crash.Value=1
        switch($case){
            'recovery' {$script:crash.Value=2}
            'type' {$script:crash.Type='String';$script:crash.Value='0'}
            'unknown' {$script:crash.Value=3}
            'host' {$script:deny='Host'}
            'holders' {$script:deny='Holders'}
            'accounts' {$script:deny='Accounts'}
            'registry' {$script:deny='Registry'}
            'corrupt' {$script:rights['S-1-5-21-1-2-3-1001']=@('SeSecurityPrivilege','SeBackupPrivilege');$script:corrupt=$true}
        }
        $plan=Plan -AllowRemoval
        if($case -in @('recovery','type','unknown','host','holders','accounts','registry')) {Assert ($plan.Blockers.Count -gt 0 -and $script:writes.Count -eq 0) "Unreadable/recovery state $case cannot produce an applicable write plan";continue}
        if($case -eq 'plan-race'){$script:rights['S-1-5-19']+=@('SeImpersonatePrivilege')}
        if($case -eq 'prewrite-race'){$script:raceAt=$script:reads+3}
        if($case -eq 'ignored'){$script:ignore=$true}
        if($case -eq 'partial'){$script:failAt=2}
        $context=New-Context;Set-WelaIntegrityControls $context $plan
        if($case -eq 'final-drift'){$script:crash.Value=1}
        if($case -eq 'preserved-drift'){$script:rights['S-1-5-19']+=@('SeImpersonatePrivilege')}
        $report=Complete-WelaConfiguration $context
        Assert ($report.ExitCode -eq 1) "Scenario $case cannot claim verified success"
        if($case -in @('plan-race','prewrite-race')){Assert ($script:writes.Count -eq 0) 'Race guard prevents the first write'}
        if($case -eq 'ignored'){Assert ($script:writes.Count -eq 1 -and $script:crash.Value -eq 1) 'Failed first write readback stops later changes'}
        if($case -eq 'partial'){Assert ($script:rights['S-1-5-20'] -contains 'SeAuditPrivilege' -and $script:crash.Value -eq 1 -and (Test-Path (Join-Path $backup 'before.jsonl'))) 'Partial failure retains verified earlier change and durable recovery record'}
        if($case -eq 'corrupt'){Assert ($script:crash.Value -eq 1) 'Unrelated-right loss is detected before the registry change'}
    }
    Reset-Fixture;$script:crash.ValueExists=$false;$script:crash.Type=$null;$script:crash.Value=$null
    $report=Configure
    Assert ($report.ExitCode -eq 0 -and $script:crash.ValueExists -and $script:crash.Type -eq 'DWord' -and $script:crash.Value -eq 0 -and $script:writes.Count -eq 1) 'Absent value is explicitly configured as DWORD zero for an exact CIS requirement'
    Reset-Fixture;$script:hostState.Role='DomainController';$script:hostState.Build=26100;$script:hostState.DomainJoined=$true;$script:hostState.DomainRole=5;$script:crash.Value=1
    $plan=Plan microsoft-sct-server2025-v2602-dc
    Assert ($plan.Blockers.Count -eq 0 -and $plan.Operations.Count -eq 0 -and @($plan.Controls|Where-Object SourceSetting -ne 'OmittedBySource').Count -eq 0) 'All three Server 2025 DC omissions remain explicit and cause no writes'
    Reset-Fixture;$script:rights['S-1-5-20']=@('SeChangeNotifyPrivilege')
    $plan=Plan;$context=New-Context
    Remove-Item -LiteralPath $script:backup -Recurse -Force
    $null=New-Item -ItemType File -Path $script:backup
    Set-WelaIntegrityControls $context $plan
    $report=Complete-WelaConfiguration $context
    Assert ($report.ExitCode -eq 1 -and $script:writes.Count -eq 0) 'Failed journal persistence prevents every native mutation'
    # Exercise production role classification with only CIM mocked.
    $nativeErrors=$null;$nativeAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'scripts/AuditIntegrity.ps1'),[ref]$null,[ref]$nativeErrors)
    $nativeHost=$nativeAst.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-WelaIntegrityHost'},$true)
    . ([scriptblock]::Create($nativeHost.Extent.Text.Replace('function Get-WelaIntegrityHost {','function Get-WelaFixtureHost {')))
    function Get-CimInstance { param($ClassName,$Filter,$ErrorAction)
        switch($ClassName) {
            'Win32_OperatingSystem' {if($script:cimDenied){throw 'CIM denied'};[pscustomobject]@{ProductType=$script:productType;BuildNumber=$script:build}}
            'Win32_ComputerSystem' {[pscustomobject]@{Name='actual-fixture';DomainRole=$script:domainRole;PartOfDomain=$script:joined}}
            'Win32_Service' {if($script:caDenied){throw 'service read denied'};if($script:caInstalled){[pscustomobject]@{Name='CertSvc'}}}
        }
    }
    $oldOS=$env:OS
    try {
        $env:OS='Windows_NT';$script:build='26100';$script:cimDenied=$false;$script:caDenied=$false;$script:caInstalled=$false
        foreach($fixture in @(@(1,0,$false,'Client'),@(1,1,$true,'Client'),@(3,2,$false,'StandaloneServer'),@(3,3,$true,'MemberServer'),@(2,4,$true,'DomainController'),@(2,5,$true,'DomainController'))) {
            $script:productType=$fixture[0];$script:domainRole=$fixture[1];$script:joined=$fixture[2]
            Assert ((Get-WelaFixtureHost).Role -eq $fixture[3]) 'Production role evidence distinguishes clients, members, standalone servers and both DC role values'
        }
        $script:caInstalled=$true
        Assert ((Get-WelaFixtureHost).CertificateAuthority -eq 'Installed') 'A CA is an independent service observation'
        $script:caDenied=$true
        Assert ((Get-WelaFixtureHost).CertificateAuthority -eq 'Unknown') 'Unreadable optional CA role is not labeled absent'
        $script:joined=$null;Reject {Get-WelaFixtureHost} 'Unknown'
        $script:joined=$false;Reject {Get-WelaFixtureHost} 'Conflicting'
        $script:joined=$true;$script:productType=1;Reject {Get-WelaFixtureHost} 'Conflicting'
        $script:productType=2;$script:build='unknown';Reject {Get-WelaFixtureHost} 'Unknown'
        $script:cimDenied=$true;Reject {Get-WelaFixtureHost} 'CIM denied'
    } finally {$env:OS=$oldOS}
    # Native code compiles on both PowerShell editions; it is never invoked by mocks.
    Initialize-WelaIntegrityNative
    Assert ($null -ne ('Wela.AuditIntegrityNative' -as [type])) 'Native adapter compiles without executing LSA writers'
    # Exercise the real early CLI boundary with all dispatch disabled.
    $errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'WELA.ps1'),[ref]$null,[ref]$errors)
    Assert ($errors.Count -eq 0) 'Public CLI parses'
    $nodes=@($ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.IfStatementAst] -and ($_.Extent.Text -match 'Integrity options require' -or $_.Extent.Text -match 'Invoke-WelaProfileCommand -Command')})
    $guard=[scriptblock]::Create('param($Cmd,$Profile,$IntegrityAction,$IntegrityProfile,$AllowPrivilegeRemoval)' + [Environment]::NewLine + (($nodes|ForEach-Object {$_.Extent.Text}) -join [Environment]::NewLine))
    function Invoke-WelaProfileCommand {throw 'Unsafe unrelated profile dispatch'}
    foreach($name in @('IntegrityAction','IntegrityProfile','AllowPrivilegeRemoval')) { $arguments=@{Cmd='configure';Profile='fixture'};$arguments[$name]=$false;Reject {& $guard @arguments} 'Integrity options require' }
    Write-Host "PASS: $script:checks audit-integrity assertions. All mutations were mocked."
} finally {Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}
