param([switch]$AllowDisposableListenerReplacement)
$ErrorActionPreference='Stop'
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not $AllowDisposableListenerReplacement -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Explicit disposable GitHub-hosted Windows listener replacement opt-in required.'}
$repo=Split-Path $PSScriptRoot -Parent;$script:ScriptRoot=$repo
Import-Module "$repo/modules/AuditProfiles.psm1" -Force
Import-Module "$repo/modules/WefSubscriptions.psm1" -Force
. "$repo/scripts/Configuration.ps1"
. "$repo/scripts/NativeChannelConfiguration.ps1"
. "$repo/scripts/WefDeployment.ps1"
. "$repo/scripts/WefArrival.ps1"
. "$repo/scripts/WecUpdate.ps1"
. "$repo/scripts/ChannelRead.ps1"
. "$repo/scripts/FirewallLoggingRecovery.ps1"
. "$repo/scripts/WecListener.ps1"
$engine=(Get-Process -Id $PID).Path
function Public([string[]]$Arguments,[int]$Code=0){
 $prior=$ErrorActionPreference;try{$ErrorActionPreference='Continue';$text=&$engine -NoLogo -NoProfile -NonInteractive -File "$repo/WELA.ps1" @Arguments 2>&1|Out-String;$actual=$LASTEXITCODE}finally{$ErrorActionPreference=$prior}
 if($actual -ne $Code){Write-Host $text;Get-ChildItem $root -Filter manifest.json -Recurse|ForEach-Object {Write-Host (Get-Content $_.FullName -Raw)};throw "Public command exit $actual differs from expected $Code"}
}

$root=Join-Path $env:RUNNER_TEMP ('wela-listener-native-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
function Save($Name,$Value){$Value|ConvertTo-Json -Depth 20|Set-Content -LiteralPath (Join-Path $root $Name) -Encoding UTF8}
function ReadListeners {
    @(Microsoft.WSMan.Management\Get-WSManInstance -ResourceURI 'http://schemas.microsoft.com/wbem/wsman/1/config/listener' -Enumerate -ErrorAction Stop|ForEach-Object {
        [pscustomobject][ordered]@{Address=[string]$_.Address;Transport=[string]$_.Transport;Port=[string]$_.Port;Hostname=[string]$_.Hostname;Enabled=[string]$_.Enabled;URLPrefix=[string]$_.URLPrefix;CertificateThumbprint=[string]$_.CertificateThumbprint;ListeningOn=@($_.ListeningOn|ForEach-Object {[string]$_}|Sort-Object);RawXml=$_.OuterXml}
    }|Sort-Object Address,Transport)
}
function Key($Value){ConvertTo-Json -InputObject @($Value|Select-Object Address,Transport,Port,Hostname,Enabled,URLPrefix,CertificateThumbprint,ListeningOn) -Depth 10 -Compress}
function ReadServices {@(Get-CimInstance Win32_Service -Filter "Name='WinRM' OR Name='Wecsvc' OR Name='MpsSvc' OR Name='BFE'"|Sort-Object Name|Select-Object Name,StartMode,State)}
function ReadFirewall {@(NetSecurity\Get-NetFirewallRule -PolicyStore ActiveStore|Sort-Object Name|Select-Object Name,Enabled,Profile,Direction,Action,PolicyStoreSourceType)}
$adapter=Join-Path $root 'checkpoint-native51.ps1'
@'
param([string]$ListenerAddress,[string]$PayloadPath)
$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$identity=[Security.Principal.WindowsIdentity]::GetCurrent();try{$sid=$identity.User.Value}finally{$identity.Dispose()}
$r=[ordered]@{EngineMajor=$PSVersionTable.PSVersion.Major;Engine=$PSVersionTable.PSVersion.ToString();ProcessId=$PID;UserSid=$sid;Status='Failed';Xml='';Diagnostic=''}
try {
 if($PSVersionTable.PSVersion.Major -ne 5 -or $ListenerAddress -notmatch '^(\*|IP:[0-9.]+)$'){throw 'Only fixture native5.1 HTTP selectors are supported.'}
 $held=[IO.File]::Open($PayloadPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try {$v=Microsoft.WSMan.Management\New-WSManInstance -ResourceURI 'http://schemas.microsoft.com/wbem/wsman/1/config/listener' -SelectorSet @{Address=$ListenerAddress;Transport='HTTP'} -FilePath $PayloadPath -ErrorAction Stop;$r.Xml=[string]$v.OuterXml;$r.Status='Created'}finally{$held.Dispose()}
}catch{$r.Diagnostic=$_.ToString()}
$r|ConvertTo-Json -Compress
if($r.Status -ne 'Created'){exit 1}
'@|Set-Content -LiteralPath $adapter -Encoding UTF8
function NewCheckpointListener($Selector,$Values) {
    $doc=[Xml.XmlDocument]::new();$element=$doc.CreateElement('cfg','Listener','http://schemas.microsoft.com/wbem/wsman/1/config/listener');$null=$doc.AppendChild($element)
    foreach($name in @('Port','Hostname','Enabled','URLPrefix','CertificateThumbprint')){$child=$doc.CreateElement('cfg',$name,$element.NamespaceURI);$child.InnerText=[string]$Values[$name];$null=$element.AppendChild($child)}
    $payload=Join-Path $root ('native-listener-'+[guid]::NewGuid().ToString('N')+'.xml');[IO.File]::WriteAllText($payload,$doc.OuterXml,[Text.UTF8Encoding]::new($false))
    $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell/v1.0/powershell.exe'
    $info.Arguments='-NoLogo -NoProfile -NonInteractive -File "'+$adapter+'" -ListenerAddress "'+$Selector.Address+'" -PayloadPath "'+$payload+'"'
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true;$info.StandardOutputEncoding=[Text.UTF8Encoding]::new($false);$info.StandardErrorEncoding=[Text.UTF8Encoding]::new($false)
    Initialize-WelaListenerPipe
    $process=[Diagnostics.Process]::new();$process.StartInfo=$info;$result=[pscustomobject]@{Started=$false;TerminationConfirmed=$false;Diagnostic=''}
    try {
        if(-not $process.Start()){throw 'Native5.1 adapter did not start.'};$result.Started=$true;$childId=$process.Id;$stdout=[Wela.ListenerPipe.Bounded]::Read($process.StandardOutput,65536);$stderr=[Wela.ListenerPipe.Bounded]::Read($process.StandardError,65536)
        if(-not $process.WaitForExit(20000)){throw 'Native5.1 adapter timed out.'};if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout,$stderr),5000)){throw 'Fixture adapter output drain timed out.'};$text=$stdout.Result;$errorText=$stderr.Result
        if($errorText -or $text.Length -gt 65536){throw 'Unexpected native adapter output.'}
        $receipt=$text|ConvertFrom-Json;Save ('adapter-'+[guid]::NewGuid().ToString('N')+'.json') $receipt
        $identity=[Security.Principal.WindowsIdentity]::GetCurrent();try{$sid=$identity.User.Value}finally{$identity.Dispose()}
        Assert ($receipt.EngineMajor -eq 5 -and $receipt.ProcessId -eq $childId -and $receipt.UserSid -ceq $sid) 'Actual native5.1 child identity must match the invoking account and observed PID.'
        if($process.ExitCode -ne 0 -or $receipt.Status -cne 'Created'){throw $receipt.Diagnostic}
        [string]$receipt.Xml
    }finally{Close-WelaListenerAdapterProcess $process $result;if($result.Diagnostic){$script:cleanupErrors+=$result.Diagnostic;Write-Host $result.Diagnostic}}
}

$services=ReadServices;$firewall=ReadFirewall;$original=$null;$fullOriginal=$null;$removed=@();$created=$false;$failure=$null;$cleanupErrors=@();$count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
try {
    $os=Get-CimInstance Win32_OperatingSystem;Assert ($os.BuildNumber -in @('20348','26100') -and $os.ProductType -eq 3) 'Standalone Server 2022/2025 fixture required.'
    $s=@($services|Where-Object Name -eq 'WinRM');Assert ($s.Count -eq 1 -and $s[0].StartMode -in @('Auto','Manual') -and $s[0].State -in @('Running','Stopped')) 'Stable non-disabled WinRM required.'
    if($s[0].State -ne 'Running'){Start-Service WinRM -ErrorAction Stop}
    $original=ReadListeners;$fullOriginal=Get-WelaListenerState;Save 'complete-original.json' $fullOriginal;Save 'listeners-original.json' $original;Save 'services-original.json' $services;Save 'firewall-original.json' $firewall
    # Replacement is a fixture-only, disposable-VM operation. Product must refuse overlaps.
    foreach($listener in @($original|Where-Object Transport -eq 'HTTP')){
        Assert ($listener.Address -match '^(\*|IP:[0-9.]+)$' -and $listener.Port -eq '5985' -and $listener.URLPrefix -eq 'wsman' -and $listener.Enabled -in @('true','false') -and -not $listener.CertificateThumbprint -and $listener.RawXml -notmatch 'Source="GPO"') 'Only ordinary local HTTP fixture listeners can be temporarily replaced.'
        Microsoft.WSMan.Management\Remove-WSManInstance -ResourceURI 'http://schemas.microsoft.com/wbem/wsman/1/config/listener' -SelectorSet @{Address=$listener.Address;Transport='HTTP'} -ErrorAction Stop
        $removed+=$listener
    }
    $ip=@(NetTCPIP\Get-NetIPAddress -AddressFamily IPv4|Where-Object {$_.AddressState -eq 'Preferred' -and $_.IPAddress -notmatch '^(127\.|169\.254\.|0\.)'}|Sort-Object IPAddress|Select-Object -First 1).IPAddress
    Assert ([bool]$ip) 'An assigned preferred IPv4 address is required.';$selector=@{Address='IP:'+$ip;Transport='HTTP'}
    $values=@{Port='5985';Hostname='';Enabled='true';URLPrefix='wsman';CertificateThumbprint=''}
    Save 'selection.json' @{Selector=$selector;Values=$values}
    $planDir=Join-Path $root 'public-plan';$applyDir=Join-Path $root 'public-apply'
    Public @('wec-listener','-WecListenerComputerName',[Environment]::MachineName,'-WecListenerLocalAddress',$ip,'-WecListenerOutputPath',$planDir)
    $plan=Get-Content (Join-Path $planDir 'manifest.json') -Raw|ConvertFrom-Json;Assert ($plan.Status -ceq 'ReviewRequired' -and -not $plan.AdapterStarted) 'Public Plan makes no native create attempt.'
    $planPath=Join-Path $planDir 'plan.json';Assert ((Get-FileHash $planPath).Hash.ToLowerInvariant() -ceq $plan.PlanHash) 'Public plan hash is exact.'
    $badDir=Join-Path $root 'bad-hash'
    Public @('wec-listener','-WecListenerAction','Apply','-WecListenerPlanPath',$planPath,'-WecListenerPlanHash',('f'*64),'-WecListenerOutputPath',$badDir) 1
    $bad=Get-Content (Join-Path $badDir 'manifest.json') -Raw|ConvertFrom-Json;Assert ($bad.Status -ceq 'Refused' -and -not $bad.AdapterStarted) 'Wrong plan hash refuses before adapter startup.'
    $created=$true
    Public @('wec-listener','-WecListenerAction','Apply','-WecListenerPlanPath',$planPath,'-WecListenerPlanHash',$plan.PlanHash,'-WecListenerOutputPath',$applyDir)
    $applied=Get-Content (Join-Path $applyDir 'manifest.json') -Raw|ConvertFrom-Json
    Assert ($applied.Status -ceq 'CreatedAndVerified' -and $applied.AdapterStarted -and $applied.NativeCreateAttempted -and $applied.Adapter.TerminationConfirmed -and $applied.Adapter.Receipt.EngineVersion -match '^5\.1\.') 'Public Apply uses the verified native5.1 adapter and confirms native creation.'
    Assert ($applied.Adapter.Receipt.ProcessId -eq $applied.Adapter.ProcessId -and $applied.Adapter.Receipt.Reader.UserSid -eq $fullOriginal.Local.Reader.UserSid -and $applied.Adapter.Receipt.Reader.AuthenticationId -eq $fullOriginal.Local.Reader.AuthenticationId) 'Actual native worker PID/account/logon is bound.'
    Assert ($applied.ReadyRuleCredit -eq 0 -and $applied.ServiceChanges -eq 0 -and $applied.AuthenticationChanges -eq 0 -and $applied.FirewallChanges -eq 0) 'No unrelated configuration changes or detection credit.'
    foreach($artifact in $applied.Artifacts){Assert ((Get-FileHash (Join-Path $applyDir $artifact.Name)).Hash.ToLowerInvariant() -ceq $artifact.Sha256) 'Retained public artifact hash matches.'}
    $replayDir=Join-Path $root 'replay'
    Public @('wec-listener','-WecListenerAction','Apply','-WecListenerPlanPath',$planPath,'-WecListenerPlanHash',$plan.PlanHash,'-WecListenerOutputPath',$replayDir) 1
    $replay=Get-Content (Join-Path $replayDir 'manifest.json') -Raw|ConvertFrom-Json;Assert ($replay.Status -ceq 'Refused' -and -not $replay.AdapterStarted) 'Actual existing listener and changed context refuse replay.'
    $overlapDir=Join-Path $root 'overlap'
    Public @('wec-listener','-WecListenerComputerName',[Environment]::MachineName,'-WecListenerLocalAddress',$ip,'-WecListenerOutputPath',$overlapDir) 1
    $overlap=Get-Content (Join-Path $overlapDir 'manifest.json') -Raw|ConvertFrom-Json;Assert ($overlap.Status -ceq 'Refused' -and -not $overlap.AdapterStarted) 'Public Plan refuses an existing HTTP5985 listener.'
    $after=ReadListeners;Save 'listeners-created.json' $after;$chosen=@($after|Where-Object {$_.Address -ceq $selector.Address -and $_.Transport -ceq 'HTTP'})
    Assert ($chosen.Count -eq 1) 'Exactly one assigned-IP listener must exist.'
    Assert ($chosen[0].Port -ceq '5985' -and $chosen[0].Enabled -ceq 'true' -and $chosen[0].URLPrefix -ceq 'wsman' -and -not $chosen[0].CertificateThumbprint -and -not $chosen[0].Hostname) 'Every fixed listener property must match.'
    Assert ($chosen[0].ListeningOn.Count -eq 1 -and $chosen[0].ListeningOn[0] -ceq $ip) 'Actual ListeningOn must contain exactly the selected IPv4 address.'
    $duplicateRejected=$false;$duplicateError=''
    try {$null=NewCheckpointListener $selector $values}catch{$duplicateRejected=$true;$duplicateError=$_.ToString()}
    Save 'collision.json' @{Rejected=$duplicateRejected;Diagnostic=$duplicateError};Assert $duplicateRejected 'Windows must reject creating the same listener selector twice.'
    Assert ((Key (ReadListeners)) -ceq (Key $after)) 'Rejected collision must preserve the listener definition.'
    $prereq=@(Get-WelaWefCollectorPrerequisites ([pscustomobject]@{CollectorFqdn='fixture.invalid';ListenerAddress=$selector.Address;IngressRuleName='WELA-checkpoint-does-not-exist';IngressLocalAddresses=@($ip);IngressRemoteAddresses=@('192.0.2.0/24')}))
    Save 'collector-prerequisite.json' $prereq;$field=@($prereq|Where-Object Name -eq 'Existing matching HTTP listener');Assert ($field.Count -eq 1 -and $field[0].Verified) 'Existing collector prerequisite must recognize the actual exact-IP listener.'
    Write-Host "PASS: $count actual public listener assertions. No WEF delivery proof."
}catch{$failure=$_.ToString();Write-Host $failure;throw}finally{
    try {if($created -and @(ReadListeners|Where-Object {$_.Address -ceq $selector.Address -and $_.Transport -ceq 'HTTP'}).Count){Microsoft.WSMan.Management\Remove-WSManInstance -ResourceURI 'http://schemas.microsoft.com/wbem/wsman/1/config/listener' -SelectorSet $selector -ErrorAction Stop}}catch{$cleanupErrors+=$_.ToString()}
    foreach($listener in $removed){try {$null=NewCheckpointListener @{Address=$listener.Address;Transport=$listener.Transport} @{Port=$listener.Port;Hostname=$listener.Hostname;Enabled=$listener.Enabled;URLPrefix=$listener.URLPrefix;CertificateThumbprint=$listener.CertificateThumbprint}}catch{$cleanupErrors+=$_.ToString()}}
    $restored=$null;$listenersOk=$false;$firewallOk=$false;$servicesOk=$false;$configurationOk=$false
    try {$restored=ReadListeners;Save 'listeners-restored.json' $restored;$listenersOk=$null -ne $original -and (Key $original) -ceq (Key $restored)}catch{$cleanupErrors+=$_.ToString()}
    try {$fullRestored=Get-WelaListenerState;Save 'complete-restored.json' $fullRestored;$configurationOk=(Get-WelaListenerReviewKey $fullOriginal) -ceq (Get-WelaListenerReviewKey $fullRestored)}catch{$cleanupErrors+=$_.ToString()}
    try {if(@($services|Where-Object Name -eq 'WinRM')[0].State -eq 'Stopped'){Stop-Service WinRM -ErrorAction Stop};$endServices=ReadServices;Save 'services-restored.json' $endServices;$servicesOk=($services|ConvertTo-Json -Compress) -ceq ($endServices|ConvertTo-Json -Compress)}catch{$cleanupErrors+=$_.ToString()}
    try {$endFirewall=ReadFirewall;Save 'firewall-restored.json' $endFirewall;$firewallOk=($firewall|ConvertTo-Json -Compress) -ceq ($endFirewall|ConvertTo-Json -Compress)}catch{$cleanupErrors+=$_.ToString()}
    Save 'cleanup.json' @{Failure=$failure;CleanupErrors=$cleanupErrors;FullConfigurationPreserved=$configurationOk;ListenersRestored=$listenersOk;ServicesRestored=$servicesOk;FirewallPreserved=$firewallOk;Complete=($configurationOk -and $listenersOk -and $servicesOk -and $firewallOk -and -not $cleanupErrors.Count);DisposableBoundary='Fixture temporarily replaced ordinary original HTTP listeners and restored their captured configuration; product creation must refuse overlap.'}
    if(-not $configurationOk -or -not $listenersOk -or -not $servicesOk -or -not $firewallOk -or $cleanupErrors.Count){throw 'Native checkpoint cleanup incomplete; inspect retained artifacts.'}
}
