param([switch]$AllowDisposableAccount,[ValidateSet('powershell','pwsh')][string]$TestEngine='powershell')
$ErrorActionPreference='Stop'
if(-not $AllowDisposableAccount -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:OS -ne 'Windows_NT'){throw 'Explicit disposable account/ACL test on a GitHub-hosted Windows runner required.'}
$computer=Get-CimInstance Win32_ComputerSystem;$os=Get-CimInstance Win32_OperatingSystem
if($computer.PartOfDomain -or $computer.DomainRole -ne 2 -or $os.ProductType -ne 3 -or [int]$os.BuildNumber -notin @(20348,26100)){throw 'Refusing domain, DC or unsupported runner.'}
$root=Split-Path $PSScriptRoot -Parent;$script:ScriptRoot=$root
Import-Module (Join-Path $root 'modules/NativeProviders.psm1') -Force
. (Join-Path $root 'scripts/WefArrival.ps1')
. (Join-Path $root 'scripts/ChannelRead.ps1')
$channel='Microsoft-Windows-CAPI2/Operational';$before=Get-WelaNativeChannel $channel
if($before.State -notin @('Enabled','Disabled') -or -not $before.SecurityDescriptor){throw 'CAPI2 full settings unavailable.'}
$nonce=[guid]::NewGuid().ToString('N');$username='WelaR'+$nonce.Substring(0,12)
$fixture=Join-Path $env:RUNNER_TEMP ('wela-channel-reader-'+$nonce);$null=New-Item -ItemType Directory $fixture
$codeRoot=Join-Path $fixture 'code';$null=New-Item -ItemType Directory $codeRoot
foreach($path in @('WELA.ps1','scripts','modules','config')){Copy-Item -LiteralPath (Join-Path $root $path) -Destination $codeRoot -Recurse}
$readerHome=Join-Path $fixture 'reader';$null=New-Item -ItemType Directory $readerHome
$engine=(Get-Command $TestEngine -ErrorAction Stop).Source
$ownedSid=$null;$aclChanged=$false;$passed=$false
$before|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $fixture 'channel-before.json') -Encoding UTF8
function NativeSettingsKey($value){Get-WelaChannelReadKey ([pscustomobject][ordered]@{Name=$value.Name;IsEnabled=$value.IsEnabled;MaximumSizeInBytes=$value.MaximumSizeInBytes;LogMode=$value.LogMode;SecurityDescriptor=$value.SecurityDescriptor})}
function Set-FixtureDescriptor([string]$Descriptor){& wevtutil.exe sl $channel ('/ca:'+$Descriptor);if($LASTEXITCODE -ne 0){throw 'Fixture channel ACL setter failed.'};$global:LASTEXITCODE=0;if((Get-WelaNativeChannel $channel).SecurityDescriptor -cne $Descriptor){throw 'Fixture channel descriptor readback differs.'}}
function Read-AsOwnedUser([string]$Label,[int]$ExpectedExit){
    $output=Join-Path $readerHome $Label
    # Credentials are passed as a SecureString through the process API, never command-line text.
    $arguments='-NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $codeRoot 'WELA.ps1')+'" channel-read -ChannelReadName "'+$channel+'" -ChannelReadOutputPath "'+$output+'"'
    $process=Start-Process -FilePath $engine -ArgumentList $arguments -Credential $credential -WorkingDirectory $readerHome -PassThru -RedirectStandardOutput (Join-Path $readerHome ($Label+'.stdout')) -RedirectStandardError (Join-Path $readerHome ($Label+'.stderr'))
    if(-not $process.WaitForExit(90000)){ $process.Kill();throw 'Reader child exceeded 90 seconds.' }
    $process.Refresh();$exitCode=$process.ExitCode;$process.Dispose()
    if($exitCode -ne $ExpectedExit){Get-Content -LiteralPath (Join-Path $readerHome ($Label+'.stderr'));throw "Reader exit $exitCode expected $ExpectedExit"}
    $report=Get-Content -LiteralPath (Join-Path $output 'result.json') -Raw|ConvertFrom-Json
    if($report.ReaderBefore.UserSid -cne $ownedSid -or $report.ReaderBefore.ElevatedAdministrator -or $report.ReaderBefore.GroupSids -contains 'S-1-5-32-544' -or $report.ReaderBefore.GroupSids -contains 'S-1-5-32-573' -or $report.ReaderBefore.TokenType -cne 'Primary'){throw 'Query did not use the owned standard-user primary token.'}
    if($report.Status -ne 'Completed' -or $report.ReadyRuleCredit -ne 0 -or $report.ConfigurationChanges -ne 0){throw 'Incomplete or overclaimed native report.'}
    $report
}
try{
    $password=ConvertTo-SecureString ('Wela!7'+[guid]::NewGuid().ToString('N')+'zA#') -AsPlainText -Force
    $user=New-LocalUser -Name $username -Password $password -Description ('WELA disposable channel-read '+$nonce) -AccountNeverExpires
    $ownedSid=$user.SID.Value
    Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $user
    $credential=[pscredential]::new(([Environment]::MachineName+'\'+$username),$password)
    # Only the owned fixture tree is made readable/writable by the owned test account.
    $acl=Get-Acl $fixture;$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($user.SID,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'));Set-Acl $fixture $acl
    $acl=Get-Acl $readerHome;$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($user.SID,'FullControl','ContainerInherit,ObjectInherit','None','Allow'));Set-Acl $readerHome $acl
    $deny=[Security.AccessControl.RawSecurityDescriptor]::new($before.SecurityDescriptor)
    if(-not $deny.DiscretionaryAcl){throw 'Fixture requires an existing DACL.'}
    $deny.DiscretionaryAcl.InsertAce(0,[Security.AccessControl.CommonAce]::new([Security.AccessControl.AceFlags]::None,[Security.AccessControl.AceQualifier]::AccessDenied,1,$user.SID,$false,$null))
    $denySddl=$deny.GetSddlForm([Security.AccessControl.AccessControlSections]::All)
    if((NativeSettingsKey (Get-WelaNativeChannel $channel)) -cne (NativeSettingsKey $before)){throw 'Channel changed before owned fixture ACL.'}
    $aclChanged=$true;Set-FixtureDescriptor $denySddl
    $denied=Read-AsOwnedUser 'denied' 1
    if($denied.Results[0].Query.Status -ne 'Denied' -or $denied.Results[0].AccessVerified){throw 'Actual owned read-deny token query was not denied.'}
    if((Get-WelaNativeChannel $channel).SecurityDescriptor -cne $denySddl){throw 'Fixture ACL drift before grant.'}
    $allow=[Security.AccessControl.RawSecurityDescriptor]::new($before.SecurityDescriptor)
    $index=0;while($index -lt $allow.DiscretionaryAcl.Count -and -not $allow.DiscretionaryAcl[$index].IsInherited){$index++}
    $allow.DiscretionaryAcl.InsertAce($index,[Security.AccessControl.CommonAce]::new([Security.AccessControl.AceFlags]::None,[Security.AccessControl.AceQualifier]::AccessAllowed,1,$user.SID,$false,$null))
    $allowSddl=$allow.GetSddlForm([Security.AccessControl.AccessControlSections]::All);Set-FixtureDescriptor $allowSddl
    $allowed=Read-AsOwnedUser 'allowed' 0
    if(-not $allowed.Results[0].AccessVerified -or $allowed.Results[0].Query.Status -notin @('ReadAllowedEmpty','EventObserved')){throw 'Actual owned read-only ACE failed to authorize the fresh standard-user query.'}
    if($denied.ReaderBefore.AuthenticationId -ceq $allowed.ReaderBefore.AuthenticationId){throw 'Expected independent fresh logon tokens.'}
    if((Get-WelaNativeChannel $channel).SecurityDescriptor -cne $allowSddl){throw 'Read-only command changed or raced fixture ACL.'}
    # A populated built-in Application log is queried under the actual administrator too.
    $admin=Invoke-WelaChannelRead @('Application') (Join-Path $fixture 'admin')
    if($admin.ExitCode -ne 0 -or $admin.Results[0].Query.Status -ne 'EventObserved'){throw 'Expected one real Application event without payload export.'}
    $passed=$true
}finally{
    $errors=@()
    if($aclChanged){try{Set-FixtureDescriptor $before.SecurityDescriptor;if((NativeSettingsKey (Get-WelaNativeChannel $channel)) -cne (NativeSettingsKey $before)){throw 'Full channel settings differ after restoration.'}}catch{$errors+=[string]$_}}
    if($ownedSid){try{$current=Get-LocalUser -Name $username -ErrorAction Stop;if($current.SID.Value -cne $ownedSid){throw 'Owned account identity changed; refusing deletion.'};Remove-LocalUser -SID $ownedSid -ErrorAction Stop;if(Get-LocalUser -SID $ownedSid -ErrorAction SilentlyContinue){throw 'Owned account remains.'}}catch{$errors+=[string]$_}}
    [pscustomobject]@{Passed=$passed;CleanupErrors=$errors;AccountSid=$ownedSid;ChannelRestored=($errors.Count -eq 0);EventGeneration='Not tested';Scope='Real fresh local standard-user CAPI2 query denial/read permission plus admin Application read; no WEF/service-token or Sigma claim'}|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $fixture 'acceptance.json') -Encoding UTF8
    if($errors.Count){throw ($errors -join '; ')}
    Write-Host "Native channel-read evidence: $fixture"
}
if(-not $passed){throw 'Native channel-read acceptance incomplete.'}
