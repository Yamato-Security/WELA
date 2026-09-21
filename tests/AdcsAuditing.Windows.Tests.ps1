param([switch]$AllowDisposableCA,[ValidateSet('powershell','pwsh')][string]$TestEngine='powershell')
$ErrorActionPreference='Stop'
if(-not $AllowDisposableCA -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:OS -ne 'Windows_NT'){throw 'Explicit disposable CA opt-in on a GitHub-hosted Windows runner is required.'}
$root=Split-Path $PSScriptRoot -Parent;$script:ScriptRoot=$root
. (Join-Path $root 'scripts/Configuration.ps1')
. (Join-Path $root 'scripts/AdcsAuditing.ps1')
Import-Module (Join-Path $root 'modules/AuditProfiles.psm1') -Force
$computer=Get-CimInstance Win32_ComputerSystem
$os=Get-CimInstance Win32_OperatingSystem
$caRoot='HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
if($computer.PartOfDomain -or $computer.DomainRole -ne 2 -or $os.ProductType -ne 3 -or [int]$os.BuildNumber -notin @(20348,26100) -or (Test-Path -LiteralPath $caRoot)){throw 'Disposable test refuses domain/DC, unknown OS or pre-existing CA configuration.'}
$beforeReport=Invoke-WelaAdcsCommand
if($beforeReport.PolicyState -ne 'NotApplicable'){throw 'Native non-CA observation did not classify the absent CA.'}
$engine=(Get-Command $TestEngine -ErrorAction Stop).Source
$nonce=[guid]::NewGuid().ToString('N');$caName='WELA-CI-'+$nonce
$privateRoot=Join-Path $env:TEMP ('wela-adcs-'+$nonce)
$null=New-Item -ItemType Directory -Path $privateRoot;Protect-WelaAdcsDirectory $privateRoot
$beforePolicies=Get-WelaEffectiveAuditPolicy
$auditGuid='0cce9221-69ae-11d9-bed3-505054503030'
$precedencePath='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$precedenceBefore=Get-WelaRegistryState -Path $precedencePath -Name SCENoApplyLegacyAuditPolicy
$beforeFeatures=@(Get-WindowsFeature | Where-Object Installed | ForEach-Object Name)
$beforeCerts=@(Get-ChildItem Cert:\LocalMachine\My,Cert:\LocalMachine\Root,Cert:\LocalMachine\CA | ForEach-Object Thumbprint)
$createdKeys=@();$createdCerts=@();$installedFeature=$false;$attemptedCA=$false;$passed=$false
[pscustomobject]@{BeforePolicies=$beforePolicies;Precedence=$precedenceBefore;Features=$beforeFeatures;CertificateThumbprints=$beforeCerts;CaName=$caName}|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $privateRoot 'before.json') -Encoding UTF8
function Invoke-TestCli {
    param([string[]]$Arguments,[int]$ExpectedExit=0)
    $ErrorActionPreference='Continue'
    try{$text=@(& $engine -NoProfile -File (Join-Path $root 'WELA.ps1') @Arguments 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference='Stop'}
    $text|ForEach-Object{Write-Host $_}
    if($code -ne $ExpectedExit){throw "Public CA CLI exit $code; expected $ExpectedExit."}
    $global:LASTEXITCODE=0
}
function Find-CreatedCertificates {
    foreach($store in @('My','Root','CA')){
        foreach($cert in @(Get-ChildItem ("Cert:\LocalMachine\"+$store)|Where-Object{$_.Subject -ceq ('CN='+$caName) -and $_.Thumbprint -notin $beforeCerts})){
            [pscustomobject]@{Store=$store;Thumbprint=$cert.Thumbprint;Certificate=$cert}
        }
    }
}
try {
    $installedFeature=$true
    $feature=Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools -ErrorAction Stop
    if(-not $feature.Success -or [string]$feature.RestartNeeded -ne 'No'){throw "CA feature is unavailable or requires restart: $($feature | Out-String). No native acceptance claim."}
    $database=Join-Path $privateRoot 'database';$logs=Join-Path $privateRoot 'database-logs'
    $null=New-Item -ItemType Directory -Path $database,$logs
    $attemptedCA=$true
    $installation=Install-AdcsCertificationAuthority -CAType StandaloneRootCA -CACommonName $caName -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -KeyLength 2048 -HashAlgorithmName SHA256 -ValidityPeriod Days -ValidityPeriodUnits 1 -DatabaseDirectory $database -LogDirectory $logs -Force -ErrorAction Stop
    $installation|Out-String|Write-Host
    if($installation.ErrorId -and $installation.ErrorId -ne 0){throw 'Disposable standalone CA installation reported failure.'}
    $native=Get-WelaAdcsSnapshot
    if($native.Status -ne 'Supported' -or $native.Active.Value -cne $caName -or $native.CaType.Value -ne 3 -or $native.Host.DomainJoined){throw ($native|ConvertTo-Json -Depth 15)}
    $createdCerts=@(Find-CreatedCertificates)
    foreach($entry in $createdCerts){
        if($entry.Certificate.HasPrivateKey){
            $rsa=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($entry.Certificate)
            try{if($rsa -isnot [Security.Cryptography.RSACng]){throw 'Unexpected disposable CA key provider.'};$createdKeys+=@($rsa.Key.KeyName)}finally{if($rsa){$rsa.Dispose()}}
        }
    }
    $createdKeys=@($createdKeys|Select-Object -Unique)
    # Test only: malformed types are observed/preserved by the real native reader.
    $null=New-ItemProperty -LiteralPath $native.Path -Name AuditFilter -Value '127' -PropertyType String -Force
    $malformedPath=Join-Path $privateRoot 'malformed.json'
    Invoke-TestCli -Arguments @('adcs-auditing','-ResultsPath',$malformedPath) -ExpectedExit 1
    $malformed=Get-Content -LiteralPath $malformedPath -Raw -Encoding UTF8|ConvertFrom-Json
    if($malformed.After.Status -ne 'Unknown' -or (Get-WelaRegistryState $native.Path AuditFilter).Type -ne 'String'){throw 'Native unknown filter type was changed or credited.'}
    # Force an actual guarded change on this newly created CA, not an idempotent-only test.
    $null=New-ItemProperty -LiteralPath $native.Path -Name AuditFilter -Value 0 -PropertyType DWord -Force
    Set-WelaEffectiveAuditPolicy -Guid $auditGuid -Mask 0 -Mode exact
    $null=New-ItemProperty -LiteralPath $precedencePath -Name SCENoApplyLegacyAuditPolicy -Value 0 -PropertyType DWord -Force
    $disabled=Get-WelaAdcsSnapshot
    if($disabled.Status -ne 'Supported' -or $disabled.AuditMask -ne 0){throw 'Actual disabled audit state (native NONE flag4) was not normalized to mask0.'}
    $applyPath=Join-Path $privateRoot 'configured.json'
    Invoke-TestCli -Arguments @('adcs-auditing','-AdcsAction','Configure','-AdcsProfile','microsoft-identity-ca-2026-09','-AllowRestart','-Auto','-BackupPath',(Join-Path $privateRoot 'journal'),'-ResultsPath',$applyPath)
    $applied=Get-Content -LiteralPath $applyPath -Raw -Encoding UTF8|ConvertFrom-Json
    if($applied.PolicyState -ne 'PolicyMatches' -or $applied.Activation -notmatch '^RestartObservedAfterWrite' -or $applied.UsableRuleCredit -ne 0){throw 'Native configuration did not verify the intended state/restart boundary.'}
    $stable=Get-WelaAdcsSnapshot;$stableKey=Get-WelaAdcsStateKey $stable
    $repeatPath=Join-Path $privateRoot 'repeated.json'
    Invoke-TestCli -Arguments @('adcs-auditing','-AdcsAction','Configure','-AdcsProfile','microsoft-identity-ca-2026-09','-AllowRestart','-Auto','-BackupPath',(Join-Path $privateRoot 'repeat-journal'),'-ResultsPath',$repeatPath)
    $repeated=Get-Content -LiteralPath $repeatPath -Raw -Encoding UTF8|ConvertFrom-Json
    if($repeated.Activation -ne 'Unverified' -or @($repeated.Results|Where-Object Status -eq 'Applied').Count -or (Get-WelaAdcsStateKey (Get-WelaAdcsSnapshot)) -cne $stableKey){throw 'Native repeat changed state or claimed historical activation.'}
    # Test-only fault injection: create an authentic failed Configure result by
    # refusing its restart. Registry writes/observations and the resumed restart
    # use real adapters. No injected helper enters the public child CLI process.
    $null=New-ItemProperty -LiteralPath $stable.Path -Name AuditFilter -Value 0 -PropertyType DWord -Force
    Restart-WelaAdcsService
    $pendingPath=Join-Path $privateRoot 'restart-pending.json'
    $pendingJournal=Join-Path $privateRoot 'restart-pending-journal'
    $restartImplementation=(Get-Command Restart-WelaAdcsService).ScriptBlock
    try {
        function Restart-WelaAdcsService { throw 'Disposable fixture: restart deliberately refused after real filter write.' }
        $pendingResult=Invoke-WelaAdcsCommand -Action Configure -Profile microsoft-identity-ca-2026-09 -AllowRestart -Auto -BackupPath $pendingJournal -ResultsPath $pendingPath
    } finally { Set-Item -Path Function:Restart-WelaAdcsService -Value $restartImplementation }
    if($pendingResult.ExitCode -ne 1 -or $pendingResult.Activation -cne 'RestartPending' -or $pendingResult.PolicyState -cne 'PolicyMatches'){throw 'Injected restart refusal did not leave authentic pending evidence with real AuditFilter127.'}
    $pendingKey=Get-WelaAdcsStateKey (Get-WelaAdcsSnapshot)
    $resumePlanRoot=Join-Path $privateRoot 'restart-plan'
    Invoke-TestCli -Arguments @('adcs-resume','-AdcsResumeJournalPath',(Join-Path $pendingJournal 'before.jsonl'),'-AdcsResumeResultsPath',$pendingPath,'-AdcsResumeOutputPath',$resumePlanRoot)
    $resumePlanPath=Join-Path $resumePlanRoot 'plan.json'
    $resumeHash=(Get-FileHash -LiteralPath $resumePlanPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Invoke-TestCli -Arguments @('adcs-resume','-AdcsResumeAction','Resume','-AdcsResumePlanPath',$resumePlanPath,'-AdcsResumePlanHash',$resumeHash,'-DryRun')
    if((Get-WelaAdcsStateKey (Get-WelaAdcsSnapshot)) -cne $pendingKey){throw 'Public resume DryRun changed the pending CA.'}
    $resumeOutput=Join-Path $privateRoot 'restart-receipts'
    Invoke-TestCli -Arguments @('adcs-resume','-AdcsResumeAction','Resume','-AdcsResumePlanPath',$resumePlanPath,'-AdcsResumePlanHash',$resumeHash,'-AdcsResumeAllowRestart','-AdcsResumeOutputPath',$resumeOutput)
    $resumed=Get-Content -LiteralPath (Join-Path $resumeOutput 'result.json') -Raw -Encoding UTF8|ConvertFrom-Json
    if($resumed.ExitCode -ne 0 -or $resumed.Status -cne 'RestartObserved' -or -not $resumed.RestartAttempted -or $resumed.ReadyRuleCredit -ne 0 -or $resumed.EventGeneration -cne 'Unverified'){throw 'Public resume did not verify the actual restart with explicit evidence limits.'}
    foreach($artifact in $resumed.Artifacts){if((Get-FileHash -LiteralPath (Join-Path $resumeOutput $artifact.Name)).Hash.ToLowerInvariant() -cne $artifact.Sha256){throw 'Public resume receipt hash mismatch.'}}
    $stable=Get-WelaAdcsSnapshot;$stableKey=Get-WelaAdcsStateKey $stable
    Invoke-TestCli -Arguments @('adcs-resume','-AdcsResumeAction','Resume','-AdcsResumePlanPath',$resumePlanPath,'-AdcsResumePlanHash',$resumeHash,'-AdcsResumeAllowRestart','-AdcsResumeOutputPath',(Join-Path $privateRoot 'replay')) -ExpectedExit 1
    if((Get-WelaAdcsStateKey (Get-WelaAdcsSnapshot)) -cne $stableKey -or (Test-Path -LiteralPath (Join-Path $privateRoot 'replay'))){throw 'Consumed pending plan restarted the CA again or created output.'}
    Write-Host 'Native pending-restart recovery passed: real filter write, injected refusal, public plan/dry-run, actual service restart, hashed receipts and replay rejection.'
    # This public CSR has no corresponding private key in the repository or runner.
    # A pending request cannot produce a usable leaf certificate; never approve it.
    $csrPath=Join-Path $PSScriptRoot 'fixtures/adcs-pending-probe.csr'
    if((Get-FileHash -LiteralPath $csrPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne 'f39e219e1ccafed480524980d07356ab6b55c1dc85cd796553d2a4a79241958b'){throw 'Fixed benign CSR changed.'}
    $request=[IO.File]::ReadAllText($csrPath)
    $startUtc=[DateTime]::UtcNow
    $client=New-Object -ComObject CertificateAuthority.Request
    try{
        # CR_IN_PKCS10 (0x100) + CR_IN_BASE64HEADER (0); source CertCli.h.
        $disposition=$client.Submit(0x100,$request,('WELAProbe:'+$nonce),($env:COMPUTERNAME+'\'+$caName))
        $requestId=$client.GetRequestId()
    }finally{if($client){$null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($client)}}
    if($disposition -ne 5 -or $requestId -le 0){throw "Expected pending disposition5, got $disposition / request$requestId. No approval, retrieval or leaf installation was performed."}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try{$requester=$identity.Name}finally{$identity.Dispose()}
    $expected=[pscustomobject]@{Computer=$env:COMPUTERNAME;RequestId=[int]$requestId;Requester=$requester;Nonce=$nonce;StartUtc=$startUtc.ToString('o');EndUtc=$null}
    $matched=@{};$deadline=[DateTime]::UtcNow.AddSeconds(30)
    do{
        $expected.EndUtc=[DateTime]::UtcNow.ToString('o')
        $events=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=@(4886,4889);StartTime=$startUtc} -MaxEvents 512 -ErrorAction SilentlyContinue -ErrorVariable queryErrors)
        if(@($queryErrors|Where-Object{$_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'}).Count){throw ($queryErrors|Out-String)}
        if($events.Count -ge 512){throw 'Native request event query cap reached; no complete-match claim.'}
        foreach($id in @(4886,4889)){
            $matches=@(foreach($event in $events){if($event.Id -eq $id){$xml=[string]::Concat($event.ToXml());if(Test-WelaAdcsRequestEvent $xml $expected $id){$xml}}})
            if($matches.Count -gt 1){throw "Ambiguous native request event$id."}
            if($matches.Count -eq 1){$matched[$id]=$matches[0]}
        }
        if($matched.Count -eq 2){break};Start-Sleep -Milliseconds 500
    }while([DateTime]::UtcNow -lt $deadline)
    if($matched.Count -ne 2){
        $events|ForEach-Object{$_.ToXml()}|Set-Content -LiteralPath (Join-Path $privateRoot 'unmatched-request-events.xml') -Encoding UTF8
        # This workgroup CA and query window belong solely to the disposable
        # test; emit bounded diagnostics before the hosted VM is discarded.
        $expected|ConvertTo-Json -Depth 5|Write-Host
        Write-Host "Native 4886/4889 records in bounded window: $($events.Count); matched: $($matched.Count)."
        $events|ForEach-Object{Write-Host $_.ToXml()}
        throw 'Both correlated native 4886 and4889 XML events were not observed. Raw bounded diagnostics retained locally.'
    }
    if((Get-WelaAdcsStateKey (Get-WelaAdcsSnapshot)) -cne $stableKey){throw 'CA identity/policy/service drifted while collecting native request events.'}
    foreach($id in @(4886,4889)){[IO.File]::WriteAllText((Join-Path $privateRoot ("event-$id.xml")),$matched[$id],[Text.UTF8Encoding]::new($false))}
    [pscustomobject]@{Kind='WelaAdcsNativeRequestComponents';Context=$stable;Expected=$expected;Disposition=$disposition;ReadyRuleCredit=0;Artifacts=@(foreach($id in @(4886,4889)){$path=Join-Path $privateRoot ("event-$id.xml");[pscustomobject]@{Path=[IO.Path]::GetFileName($path);Sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()}});Scope='Local pending request only; no enterprise-template/DC/Sigma/backend proof'}|ConvertTo-Json -Depth 18|Set-Content -LiteralPath (Join-Path $privateRoot 'native-components.json') -Encoding UTF8
    foreach($id in @(4886,4889)){Write-Host $matched[$id]}
    Get-Content -LiteralPath (Join-Path $privateRoot 'native-components.json') -Raw -Encoding UTF8|Write-Host
    $passed=$true
    Write-Host "Observed correlated Security4886/4889 request$requestId on disposable Server$($os.BuildNumber) via $TestEngine; no certificate was approved."
}catch{
    # Preserve the primary native failure even if cleanup independently fails.
    Write-Host ('Native CA validation failed before cleanup: '+($_|Out-String))
    Write-Host $_.ScriptStackTrace
    throw
}finally{
    $cleanupErrors=@()
    if($attemptedCA){
        try{
            $current=Get-WelaRegistryState -Path $caRoot -Name Active
            if($current.ValueExists -and $current.Value -cne $caName){throw 'Active CA no longer belongs to this test; cleanup refused.'}
            $createdCerts=@(Find-CreatedCertificates)
            foreach($entry in $createdCerts){if($entry.Certificate.HasPrivateKey){$rsa=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($entry.Certificate);try{if($rsa -is [Security.Cryptography.RSACng]){$createdKeys+=@($rsa.Key.KeyName)}}finally{if($rsa){$rsa.Dispose()}}}}
            Uninstall-AdcsCertificationAuthority -Force -ErrorAction Stop|Out-Null
            foreach($entry in $createdCerts){$path='Cert:\LocalMachine\'+$entry.Store+'\'+$entry.Thumbprint;if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -ErrorAction Stop}}
            foreach($keyName in @($createdKeys|Select-Object -Unique)){
                $provider=[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
                if([Security.Cryptography.CngKey]::Exists($keyName,$provider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)){$key=[Security.Cryptography.CngKey]::Open($keyName,$provider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey);try{$key.Delete()}finally{$key.Dispose()}}
            }
        }catch{$cleanupErrors+=$_.Exception.Message}
    }
    try{
        Set-WelaEffectiveAuditPolicy -Guid $auditGuid -Mask $beforePolicies[$auditGuid] -Mode exact
        if($precedenceBefore.ValueExists){$null=New-ItemProperty -LiteralPath $precedencePath -Name SCENoApplyLegacyAuditPolicy -Value $precedenceBefore.Value -PropertyType $precedenceBefore.Type -Force}else{Remove-ItemProperty -LiteralPath $precedencePath -Name SCENoApplyLegacyAuditPolicy -ErrorAction SilentlyContinue}
        $after=Get-WelaRegistryState -Path $precedencePath -Name SCENoApplyLegacyAuditPolicy
        if(($after|ConvertTo-Json -Compress) -cne ($precedenceBefore|ConvertTo-Json -Compress)){throw 'Audit precedence restoration differs.'}
        $afterPolicies=Get-WelaEffectiveAuditPolicy
        foreach($guid in $beforePolicies.Keys){if($afterPolicies[$guid] -ne $beforePolicies[$guid]){throw "Audit policy restoration differs: $guid"}}
    }catch{$cleanupErrors+=$_.Exception.Message}
    $featureRemoval=[pscustomobject]@{CaAndAuditRestored=($cleanupErrors.Count -eq 0);Attempted=$false;Features=@();Success=$null;RestartNeeded=$null;Boundary='OS feature removal is separate from CA/audit restoration and can require disposal of the hosted runner.'}
    if($installedFeature -and $cleanupErrors.Count -eq 0){
        try{
            if((Get-WelaRegistryState -Path $caRoot -Name Active).ValueExists){throw 'A configured CA remains; feature cleanup refused.'}
            $added=@(Get-WindowsFeature|Where-Object{$_.Installed -and $_.Name -notin $beforeFeatures -and ($_.Name -like 'ADCS-*' -or $_.Name -in @('AD-Certificate','RSAT-ADCS','RSAT-ADCS-Mgmt'))}|ForEach-Object Name)
            if($added.Count){
                $featureRemoval.Attempted=$true;$featureRemoval.Features=$added
                $removed=Uninstall-WindowsFeature -Name $added -ErrorAction Stop
                $featureRemoval.Success=[bool]$removed.Success;$featureRemoval.RestartNeeded=[string]$removed.RestartNeeded
                if(-not $removed.Success -or [string]$removed.RestartNeeded -notin @('No','Yes')){throw 'Created CA feature removal failed or returned an unknown restart status.'}
                # GitHub destroys this isolated VM after the job. No production
                # restart and no complete OS feature-restoration claim are made.
            }
        }catch{$cleanupErrors+=$_.Exception.Message}
    }
    $featureRemoval|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $privateRoot 'feature-removal.json') -Encoding UTF8
    $featureRemoval|ConvertTo-Json -Depth 5|Write-Host
    if($cleanupErrors.Count){throw "Disposable CA cleanup failed; receipt retained at $privateRoot : $($cleanupErrors -join '; ')"}
    if($passed){Remove-Item -LiteralPath $privateRoot -Recurse -Force}
}
$global:LASTEXITCODE=0
Write-Host 'PASS: actual public CA configuration, idempotence, pending-restart resume, pending-request events and exact audit/created-CA restoration. Requested OS feature removal can await hosted-runner disposal, as recorded separately.'
