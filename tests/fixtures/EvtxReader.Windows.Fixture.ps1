# Test-only account/owned-file ACL fixture; never loaded by the product.
function Invoke-WelaEvtxReaderFixture {
    param([string]$ProbePath,[string]$ArchivePath,[string]$FixtureParent,[string]$EnginePath,[switch]$AllowDisposableAccount)
    if (-not $AllowDisposableAccount -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:OS -ne 'Windows_NT') {throw 'Explicit disposable account/file-ACL opt-in on a GitHub-hosted Windows runner is required.'}
    $computer=Get-CimInstance Win32_ComputerSystem;$os=Get-CimInstance Win32_OperatingSystem
    if ($computer.PartOfDomain -or $computer.DomainRole -ne 2 -or $os.ProductType -ne 3 -or [int]$os.BuildNumber -notin @(20348,26100)) {throw 'Archive reader fixture refuses domain/DC or unsupported hosts.'}
    $repo=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $nonce=[guid]::NewGuid().ToString('N');$username='WelaE'+$nonce.Substring(0,12)
    $fixture=New-WelaEvtxOutput -Path (Join-Path $FixtureParent ('archive-reader-'+$nonce)) -SourcePath $ProbePath
    $codeRoot=Join-Path $fixture 'code';$null=New-Item -ItemType Directory $codeRoot
    foreach ($path in @('WELA.ps1','scripts','modules','config')) {Copy-Item -LiteralPath (Join-Path $repo $path) -Destination $codeRoot -Recurse}
    $probe=Join-Path $fixture 'probe';Copy-Item -LiteralPath $ProbePath -Destination $probe -Recurse
    $archive=Join-Path $fixture 'probe.evtx';Copy-Item -LiteralPath $ArchivePath -Destination $archive
    $readerHome=Join-Path $fixture 'reader';$null=New-Item -ItemType Directory $readerHome
    $archiveHash=(Get-FileHash -LiteralPath $archive).Hash.ToLowerInvariant();$archiveBytes=(Get-Item -LiteralPath $archive).Length
    $source=Import-WelaEvtxProbe $probe
    $sourceSid=([xml]$source.Files['event.xml'].Text).GetElementsByTagName('Data')|Where-Object {$_.GetAttribute('Name') -ceq 'SubjectUserSid'}|ForEach-Object InnerText
    $ownedSid=$null;$passed=$false;$beforeArchiveAcl=$null;$counter=[pscustomobject]@{Count=0}
    function Check($Value,[string]$Message) {if (-not $Value) {throw $Message};$counter.Count++}
    function Read-AsOwnedUser([string]$Label,[int]$ExpectedExit) {
        $output=Join-Path $readerHome $Label
        $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$EnginePath
        $start.Arguments='-NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $codeRoot 'WELA.ps1')+'" evtx-recovery -EvtxAction Verify -EvtxProbePath "'+$probe+'" -EvtxArchivePath "'+$archive+'" -EvtxOutputPath "'+$output+'"'
        $start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.WorkingDirectory=$readerHome
        $start.UserName=$username;$start.Domain=[Environment]::MachineName;$start.Password=$password;$start.LoadUserProfile=$true
        $start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
        $start.EnvironmentVariables['TEMP']=$readerHome;$start.EnvironmentVariables['TMP']=$readerHome
        $process=[Diagnostics.Process]::new();$process.StartInfo=$start;$started=$false
        try {
            if (-not $process.Start()) {throw 'Owned archive-reader process did not start.'};$started=$true
            $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
            if (-not $process.WaitForExit(90000)) {$process.Kill();$null=$process.WaitForExit(5000);throw 'Owned archive-reader process exceeded 90 seconds.'}
            if (-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout,$stderr),5000)) {throw 'Owned reader output pipes did not close.'}
            $exitCode=$process.ExitCode
            [IO.File]::WriteAllText((Join-Path $readerHome ($Label+'.stdout')),$stdout.GetAwaiter().GetResult())
            [IO.File]::WriteAllText((Join-Path $readerHome ($Label+'.stderr')),$stderr.GetAwaiter().GetResult())
        } finally {
            try {if ($started -and -not $process.HasExited) {$process.Kill();if (-not $process.WaitForExit(5000)) {throw 'Owned reader termination was not confirmed.'}}} finally {$process.Dispose()}
        }
        if ($exitCode -ne $ExpectedExit) {Get-Content -LiteralPath (Join-Path $readerHome ($Label+'.stderr'))|Write-Host;Get-Content -LiteralPath (Join-Path $readerHome ($Label+'.stdout'))|Write-Host;throw "Owned archive-reader exit $exitCode expected $ExpectedExit"}
        $report=ConvertFrom-WelaEvtxJson (Get-Content -LiteralPath (Join-Path $output 'manifest.json') -Raw)
        if ($report.SchemaVersion -ne 2 -or $report.ReaderBefore.UserSid -cne $ownedSid -or $report.ReaderBefore.ElevatedAdministrator -or $report.ReaderBefore.GroupSids -contains 'S-1-5-32-544' -or $report.ReaderBefore.GroupSids -contains 'S-1-5-32-573' -or $report.ReaderBefore.TokenType -cne 'Primary' -or $report.ReaderBefore.Impersonation -cne 'Absent') {throw 'Archive query did not use the owned standard-user primary token.'}
        if (-not $report.ReaderStable -or (Get-WelaEvtxRecoveryKey $report.ReaderBefore) -cne (Get-WelaEvtxRecoveryKey $report.ReaderAfter) -or $report.ReadyRuleCredit -ne 0 -or $report.PolicyChanges -ne 0) {throw 'Reader token changed or the report overclaimed configuration/readiness.'}
        $report
    }
    try {
        $password=ConvertTo-SecureString ('Wela!7'+[guid]::NewGuid().ToString('N')+'zA#') -AsPlainText -Force
        $user=New-LocalUser -Name $username -Password $password -Description ('WELA EVTX reader '+$nonce) -AccountNeverExpires
        $ownedSid=$user.SID.Value;Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $user
        $acl=Get-Acl -LiteralPath $fixture;$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($user.SID,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'));Set-Acl -LiteralPath $fixture -AclObject $acl
        $acl=Get-Acl -LiteralPath $readerHome;$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($user.SID,'FullControl','ContainerInherit,ObjectInherit','None','Allow'));Set-Acl -LiteralPath $readerHome -AclObject $acl
        # Only the owned copy is changed; source/producer ACLs and system logs remain intact.
        $beforeArchiveAcl=(Get-Acl -LiteralPath $archive).Sddl
        $deny=[Security.AccessControl.FileSystemAccessRule]::new($user.SID,'ReadData','Deny')
        $acl=Get-Acl -LiteralPath $archive;$acl.AddAccessRule($deny);Set-Acl -LiteralPath $archive -AclObject $acl
        $denied=Read-AsOwnedUser 'denied' 1
        Check ($denied.Status -eq 'Unverified' -and $denied.FileReadAccess -eq 'Denied' -and $denied.NativeError -eq 5 -and $denied.FailureStage -eq 'ArchiveFileOpen' -and $denied.NativeQuery -eq 'NotAttempted' -and $denied.RecoveredEvents -eq 0 -and $null -eq $denied.ArchiveSha256) 'Real file-read denial was misreported as native query or recovery success.'
        Check (-not (Test-Path -LiteralPath (Join-Path $denied.OutputPath 'recovered-event.xml'))) 'Denied reader emitted a recovered event.'
        $acl=Get-Acl -LiteralPath $archive;$acl.RemoveAccessRuleSpecific($deny);Set-Acl -LiteralPath $archive -AclObject $acl
        Check ((Get-Acl -LiteralPath $archive).Sddl -ceq $beforeArchiveAcl) 'Owned archive ACL differs after removing only the fixture deny.'
        $allowed=Read-AsOwnedUser 'allowed' 0
        Check ($allowed.Status -eq 'NativeEventRecovered' -and $allowed.FileReadAccess -eq 'Allowed' -and $allowed.NativeQuery -eq 'ExactEventRecovered' -and $allowed.RecoveredEvents -eq 1) 'Fresh standard user did not recover the exact native event.'
        Check ($allowed.ArchiveSha256 -ceq $archiveHash -and $allowed.ArchiveBytes -eq $archiveBytes) 'Owned reader recovered different archive bytes.'
        Check ($allowed.NativeLogStatus.Count -eq 1 -and $allowed.NativeLogStatus[0].StatusCode -eq 0 -and $allowed.NativeLogStatus[0].LogName -ieq $archive) 'Native file-query status was not bound to the exact archive.'
        Check ($denied.ReaderBefore.AuthenticationId -cne $allowed.ReaderBefore.AuthenticationId -and $denied.ReaderBefore.TokenId -cne $allowed.ReaderBefore.TokenId) 'Expected independent fresh logon and token identities.'
        Check ($sourceSid -and $sourceSid -cne $allowed.ReaderBefore.UserSid -and $allowed.SourceComputer -ceq $source.Event.Computer) 'Archive reader and original producer identities were conflated.'
        $recovered=[IO.File]::ReadAllText((Join-Path $allowed.OutputPath 'recovered-event.xml'))
        Check ((Read-WelaEvtxEvent $recovered).Key -ceq $source.Event.Key) 'Independently reopened event differs from the producer probe.'
        foreach ($artifact in $allowed.Artifacts) {Check ((Get-FileHash -LiteralPath (Join-Path $allowed.OutputPath $artifact.Name)).Hash.ToLowerInvariant() -ceq $artifact.Sha256) 'Owned reader evidence hash differs.'}
        Check ((Import-WelaEvtxProbe $probe).Fingerprint -ceq $source.Fingerprint -and (Get-FileHash -LiteralPath $archive).Hash.ToLowerInvariant() -ceq $archiveHash -and (Get-Acl -LiteralPath $archive).Sddl -ceq $beforeArchiveAcl) 'Read-only recovery changed source evidence or its file ACL.'
        $passed=$true
    } finally {
        $errors=@()
        if ($beforeArchiveAcl) {try {$acl=Get-Acl -LiteralPath $archive;$acl.SetSecurityDescriptorSddlForm($beforeArchiveAcl);Set-Acl -LiteralPath $archive -AclObject $acl;if ((Get-Acl -LiteralPath $archive).Sddl -cne $beforeArchiveAcl) {throw 'Owned archive ACL restoration differs.'}} catch {$errors+=[string]$_}}
        if ($ownedSid) {try {$current=Get-LocalUser -Name $username -ErrorAction Stop;if ($current.SID.Value -cne $ownedSid) {throw 'Owned account identity changed; refusing deletion.'};Remove-LocalUser -SID $ownedSid -ErrorAction Stop;if (Get-LocalUser -SID $ownedSid -ErrorAction SilentlyContinue) {throw 'Owned account remains.'}} catch {$errors+=[string]$_}}
        [pscustomobject]@{Passed=$passed;Checks=$counter.Count;CleanupErrors=$errors;AccountSid=$ownedSid;ArchiveSha256=$archiveHash;Scope='Fresh standard-user file denial and exact native 4688 EVTX recovery; no channel/service-token, backend, archive-duration or Sigma claim'}|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $fixture 'acceptance.json') -Encoding UTF8
        if ($errors.Count) {throw ($errors -join '; ')}
    }
    if (-not $passed) {throw 'Owned archive-reader acceptance incomplete.'}
    Write-Host "Native EVTX standard-reader proof: $($counter.Count) assertions; fresh denied/allowed logons, exact 4688, original producer distinct, owned file ACL restored and account removed. Engine: $EnginePath"
}
