param([switch]$AllowDisposableWriter,[ValidateSet('powershell','pwsh')][string]$TestEngine='powershell')
$ErrorActionPreference='Stop'
if(-not $AllowDisposableWriter -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:OS -ne 'Windows_NT'){throw 'Explicit disposable writer/policy/ACL opt-in on a GitHub-hosted Windows runner required.'}
$computer=Get-CimInstance Win32_ComputerSystem;$os=Get-CimInstance Win32_OperatingSystem
if($computer.PartOfDomain -or $computer.DomainRole -ne 2 -or $os.ProductType -ne 3 -or [int]$os.BuildNumber -notin @(20348,26100)){throw 'Refusing domain, DC or unknown runner.'}
$root=Split-Path $PSScriptRoot -Parent;$script:ScriptRoot=$root
. (Join-Path $root 'scripts/PowerShellTranscription.ps1')
$nonce=[guid]::NewGuid().ToString('N');$username='WelaT'+$nonce.Substring(0,12)
$fixture=Join-Path $env:RUNNER_TEMP ('wela-transcript-probe-'+$nonce);$null=New-Item -ItemType Directory $fixture
$codeRoot=Join-Path $fixture 'code';$null=New-Item -ItemType Directory $codeRoot
foreach($path in @('WELA.ps1','scripts','modules','config')){Copy-Item -LiteralPath (Join-Path $root $path) -Destination $codeRoot -Recurse}
$readerHome=Join-Path $fixture 'writer';$destination=Join-Path $fixture 'transcripts';$null=New-Item -ItemType Directory $readerHome,$destination
$engine=(Get-Command $TestEngine -ErrorAction Stop).Source
$policyBefore=@(Get-WelaTranscriptPolicy @('Registry64','Registry32'));$policyBefore|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $fixture 'policy-before.json') -Encoding UTF8
$ownedSid=$null;$policyTouched=$false;$passed=$false;$originalAcl=$null
function Restore-Policy {
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64);$key=$null
    try{
        $key=$base.CreateSubKey('SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription')
        $key.SetValue('EnableTranscripting',0,[Microsoft.Win32.RegistryValueKind]::DWord)
        foreach($name in @('OutputDirectory','EnableInvocationHeader','EnableTranscripting')){
            $value=$policyBefore[0].Machine.$name
            if($value.ValueExists){$key.SetValue($name,$value.Value,[Microsoft.Win32.RegistryValueKind]([string]$value.Type))}else{$key.DeleteValue($name,$false)}
        }
        $remove=-not $policyBefore[0].Machine.EnableTranscripting.KeyExists -and $key.GetValueNames().Count -eq 0 -and $key.GetSubKeyNames().Count -eq 0
        $key.Dispose();$key=$null
        if($remove){$base.DeleteSubKey('SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription',$false)}
    }finally{if($key){$key.Dispose()};$base.Dispose()}
    if((@(Get-WelaTranscriptPolicy @('Registry64','Registry32'))|ConvertTo-Json -Depth 12 -Compress) -cne ($policyBefore|ConvertTo-Json -Depth 12 -Compress)){throw 'Exact typed transcription policy/key restoration failed.'}
}
function Invoke-ProbeAsOwnedUser([string]$Label,[int]$ExpectedExit,[ValidateSet('Plan','Run')][string]$Action='Run'){
    $output=Join-Path $readerHome $Label
    # Credentials are passed as a SecureString through the process API, never command-line text.
    $arguments='-NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $codeRoot 'WELA.ps1')+'" transcript-probe -TranscriptProbeAction '+$Action+' -TranscriptProbeDirectory "'+$destination+'"'+$(if($Action -eq 'Run'){' -TranscriptProbeOutputPath "'+$output+'"'}else{''})
    # Own the process handle directly: Windows PowerShell's Start-Process can lose
    # ExitCode for alternate-credential children after they exit.
    $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$engine;$start.Arguments=$arguments
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.WorkingDirectory=$readerHome
    $start.UserName=$username;$start.Domain=[Environment]::MachineName;$start.Password=$password;$start.LoadUserProfile=$true
    $start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $start.EnvironmentVariables['TEMP']=$readerHome;$start.EnvironmentVariables['TMP']=$readerHome
    $process=[Diagnostics.Process]::new();$process.StartInfo=$start;$started=$false
    try{
        if(-not $process.Start()){throw 'Native reader process did not start.'};$started=$true
        $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit(90000)){$process.Kill();$null=$process.WaitForExit(5000);throw 'Reader child exceeded 90 seconds.'}
        if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout,$stderr),5000)){throw 'Reader output pipes did not close within five seconds of process exit.'}
        $exitCode=$process.ExitCode
        [IO.File]::WriteAllText((Join-Path $readerHome ($Label+'.stdout')),$stdout.GetAwaiter().GetResult())
        [IO.File]::WriteAllText((Join-Path $readerHome ($Label+'.stderr')),$stderr.GetAwaiter().GetResult())
    }finally{
        try{if($started -and -not $process.HasExited){$process.Kill();if(-not $process.WaitForExit(5000)){throw 'Reader child termination was not confirmed; no acceptance claim.'}}}finally{$process.Dispose()}
    }
    if($exitCode -ne $ExpectedExit){Get-Content -LiteralPath (Join-Path $readerHome ($Label+'.stderr'));throw "Reader exit $exitCode expected $ExpectedExit"}
    if($Action -eq 'Plan'){if(Test-Path -LiteralPath $output){throw 'Plan wrote explicit evidence output.'};return}
    $report=Get-Content -LiteralPath (Join-Path $output 'result.json') -Raw|ConvertFrom-Json
    if($report.ReadyRuleCredit -ne 0 -or $report.SigmaEvtxCredit -ne 0 -or $report.ConfigurationChanges -ne 0){throw 'Transcript report overclaims coverage or changed configuration.'}
    $report
}
try{
    $password=ConvertTo-SecureString ('Wela!7'+[guid]::NewGuid().ToString('N')+'zA#') -AsPlainText -Force
    $user=New-LocalUser -Name $username -Password $password -Description ('WELA transcript '+$nonce.Substring(0,20)) -AccountNeverExpires
    $ownedSid=$user.SID.Value;Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $user
    $acl=Get-Acl $fixture;$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($user.SID,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'));Set-Acl $fixture $acl
    $acl=Get-Acl $readerHome;$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($user.SID,'FullControl','ContainerInherit,ObjectInherit','None','Allow'));Set-Acl $readerHome $acl
    $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
    foreach($sid in @('S-1-5-18','S-1-5-32-544',$ownedSid)){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
    Set-Acl $destination $acl;$originalAcl=Get-Acl $destination
    $policyTouched=$true
    Set-WelaTranscriptRegistryValue -Name OutputDirectory -Value $destination -Type String
    Set-WelaTranscriptRegistryValue -Name EnableTranscripting -Value 1 -Type DWord
    # Exercise invocation headers while preserving the real original typed preference.
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    try{$key=$base.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription',$true);try{$key.SetValue('EnableInvocationHeader',1,[Microsoft.Win32.RegistryValueKind]::DWord)}finally{$key.Dispose()}}finally{$base.Dispose()}
    $configured=@(Get-WelaTranscriptPolicy @('Registry64','Registry32'))|ConvertTo-Json -Depth 12 -Compress
    Invoke-ProbeAsOwnedUser 'plan' 0 'Plan'
    $allowed=Invoke-ProbeAsOwnedUser 'allowed' 0
    if($allowed.Status -ne 'CompletedAutomaticTranscript' -or $allowed.WriterAuthorization -ne 'ObservedForThisChild' -or $allowed.Worker.BeforeToken.Sid -cne $ownedSid -or $allowed.ParentBefore.Sid -cne $ownedSid -or $allowed.Worker.BeforeToken.AuthenticationId -cne $allowed.ParentBefore.AuthenticationId -or @($allowed.Worker.BeforeToken.Groups|Where-Object Sid -eq 'S-1-5-32-544').Count){throw 'No completed automatic native5.1 transcript from the actual owned standard-user logon.'}
    if($allowed.Worker.Engine -notlike '*\System32\WindowsPowerShell\v1.0\powershell.exe' -or $allowed.Worker.Edition -cne 'Desktop'){throw 'Wrong transcript engine.'}
    $artifact=@($allowed.Artifacts|Where-Object Name -eq 'transcript.txt')
    if($artifact.Count -ne 1 -or (Get-FileHash -LiteralPath (Join-Path $allowed.OutputPath 'transcript.txt') -Algorithm SHA256).Hash.ToLowerInvariant() -cne $artifact[0].Sha256){throw 'Transcript evidence hash mismatch.'}
    if((@(Get-WelaTranscriptPolicy @('Registry64','Registry32'))|ConvertTo-Json -Depth 12 -Compress) -cne $configured -or (Get-Acl $destination).Sddl -cne $originalAcl.Sddl){throw 'Probe changed configured policy or root ACL.'}
    $deny=Get-Acl $destination
    $deny.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($user.SID,'Write','ContainerInherit,ObjectInherit','None','Deny'));Set-Acl $destination $deny
    $deniedAcl=(Get-Acl $destination).Sddl
    $denied=Invoke-ProbeAsOwnedUser 'denied' 1
    if($denied.Status -eq 'CompletedAutomaticTranscript' -or $denied.WriterAuthorization -ne 'Unverified' -or $denied.Transcript){throw 'Denied writer gained positive transcript proof.'}
    if((Get-Acl $destination).Sddl -cne $deniedAcl -or (@(Get-WelaTranscriptPolicy @('Registry64','Registry32'))|ConvertTo-Json -Depth 12 -Compress) -cne $configured){throw 'Denied run changed the explicit deny or policy.'}
    $passed=$true
}finally{
    $errors=@()
    if($policyTouched){try{Restore-Policy}catch{$errors+=[string]$_}}
    if($originalAcl){try{Set-Acl $destination $originalAcl;if((Get-Acl $destination).Sddl -cne $originalAcl.Sddl){throw 'Owned destination ACL restoration failed.'}}catch{$errors+=[string]$_}}
    if($ownedSid){try{$current=Get-LocalUser -Name $username -ErrorAction Stop;if($current.SID.Value -cne $ownedSid){throw 'Account identity changed; refusing deletion.'};Remove-LocalUser -SID $ownedSid -ErrorAction Stop;if(Get-LocalUser -SID $ownedSid -ErrorAction SilentlyContinue){throw 'Owned account remains.'}}catch{$errors+=[string]$_}}
    [pscustomobject]@{Passed=$passed;CleanupErrors=$errors;OwnedSid=$ownedSid;PolicyRestored=($errors.Count -eq 0);Scope='Actual local standard-user automatic native5.1 transcript and explicit denied writer; no UNC, PS7-session, collector or Sigma claim'}|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $fixture 'acceptance.json') -Encoding UTF8
    Write-Host "Native automatic transcript evidence: $fixture"
    if($errors.Count){throw ($errors -join '; ')}
}
if(-not $passed){throw 'Native transcript acceptance incomplete.'}
