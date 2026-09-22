# One reviewed exact-IP HTTP listener; native creation always runs in Windows PowerShell 5.1.
function Get-WelaListenerKey {
    param($Value)
    # Windows PowerShell 5.1 escapes these HTML characters even with default JSON settings.
    # Normalize the same spelling in both engines before binding nested context strings.
    $json=ConvertTo-Json -InputObject $Value -Depth 24 -Compress
    $json.Replace('<','\u003c').Replace('>','\u003e').Replace('&','\u0026').Replace("'",'\u0027')
}
function Get-WelaListenerSelection {
    param($ComputerName,$LocalAddress)
    if($ComputerName -isnot [string] -or $ComputerName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,62}$'){throw 'Select the actual local computer name.'}
    if($LocalAddress -isnot [string] -or $LocalAddress -cnotmatch '^([0-9]{1,3}\.){3}[0-9]{1,3}$'){throw 'Select one canonical assigned IPv4 address.'}
    $pieces=$LocalAddress.Split('.')
    foreach($part in $pieces){if([int]$part -gt 255 -or ([int]$part).ToString() -cne $part){throw 'Select one canonical assigned IPv4 address.'}}
    if([int]$pieces[0] -in @(0,127) -or [int]$pieces[0] -ge 224 -or ($pieces[0] -eq '169' -and $pieces[1] -eq '254')){throw 'Unspecified, loopback, link-local and multicast/reserved addresses are unsupported.'}
    [pscustomobject][ordered]@{ComputerName=$ComputerName.ToUpperInvariant();LocalAddress=$LocalAddress}
}
function ConvertFrom-WelaListenerXml {
    param([string]$Xml)
    if(-not $Xml -or $Xml.Length -gt 131072){throw 'Listener XML exceeds its bound or is absent.'}
    $doc=Read-WelaWefXml $Xml;$root=$doc.DocumentElement;$ns='http://schemas.microsoft.com/wbem/wsman/1/config/listener'
    if($root.LocalName -cne 'Listener' -or $root.NamespaceURI -cne $ns){throw 'Unexpected native listener root.'}
    $fields=@('Address','Transport','Port','Hostname','Enabled','URLPrefix','CertificateThumbprint');$result=[ordered]@{};$policy=$false
    foreach($node in @($root)+@($root.ChildNodes|Where-Object NodeType -eq Element)){
        foreach($attr in @($node.Attributes)){
            if($attr.NamespaceURI -eq 'http://www.w3.org/2000/xmlns/' -or ($node -eq $root -and $attr.NamespaceURI -eq 'http://www.w3.org/XML/1998/namespace' -and $attr.LocalName -eq 'lang')){continue}
            if($attr.Name -cne 'Source' -or -not $attr.Value){throw 'Unsupported listener provenance attribute.'};$policy=$true
        }
    }
    foreach($child in $root.ChildNodes){if($child.NodeType -eq 'ProcessingInstruction' -or ($child.NodeType -in @('Text','CDATA') -and -not [string]::IsNullOrWhiteSpace($child.Value))){throw 'Unsupported listener container text.'}}
    foreach($child in @($root.ChildNodes|Where-Object NodeType -eq Element)){
        if($child.NamespaceURI -cne $ns -or $child.LocalName -cnotin ($fields+@('ListeningOn')) -or @($child.ChildNodes|Where-Object NodeType -in @('Element','ProcessingInstruction')).Count){throw 'Unsupported native listener field.'}
    }
    foreach($name in $fields){$nodes=@($root.ChildNodes|Where-Object {$_.NodeType -eq 'Element' -and $_.LocalName -ceq $name});if($nodes.Count -ne 1){throw "Listener field is absent or duplicated: $name"};$result[$name]=[string]$nodes[0].InnerText}
    if(-not $result.Address -or $result.Address.Length -gt 256 -or $result.Transport -cnotin @('HTTP','HTTPS') -or $result.Port -cnotmatch '^[1-9][0-9]{0,4}$' -or [int]$result.Port -gt 65535 -or $result.Enabled -cnotin @('true','false') -or $result.Hostname.Length -gt 255 -or $result.URLPrefix -cnotmatch '^[A-Za-z0-9_]+(?:/[A-Za-z0-9_]+)*$' -or $result.CertificateThumbprint -cnotmatch '^(|[0-9A-Fa-f]{40})$'){throw 'Unsupported native listener values.'}
    $listening=@($root.ChildNodes|Where-Object {$_.NodeType -eq 'Element' -and $_.LocalName -ceq 'ListeningOn'}|ForEach-Object InnerText|Sort-Object)
    if($listening.Count -gt 64 -or @($listening|Sort-Object -Unique).Count -ne $listening.Count){throw 'Ambiguous or excessive ListeningOn addresses.'}
    foreach($value in $listening){$ip=$null;if(-not [Net.IPAddress]::TryParse($value,[ref]$ip)){throw 'Invalid native ListeningOn address.'}}
    $result.ListeningOn=$listening;$result.PolicyOwned=$policy;$result.RawXml=$Xml
    [pscustomobject]$result
}
function Read-WelaListenerInventory {
    $values=@(Microsoft.WSMan.Management\Get-WSManInstance -ResourceURI 'http://schemas.microsoft.com/wbem/wsman/1/config/listener' -Enumerate -ErrorAction Stop|Select-Object -First 33)
    if($values.Count -gt 32){throw 'Listener inventory exceeds 32 entries.'}
    $seen=@{};$bytes=0
    $rows=@(foreach($value in $values){$row=ConvertFrom-WelaListenerXml ([string]$value.OuterXml);$bytes+=$row.RawXml.Length;$id=$row.Address+'|'+$row.Transport;if($seen.ContainsKey($id) -or $bytes -gt 1048576){throw 'Duplicate or oversized listener inventory.'};$seen[$id]=$true;$row})
    @($rows|Sort-Object Address,Transport)
}
function Assert-WelaListenerAbsent {
    param([object[]]$Listeners,$Selection)
    foreach($row in $Listeners){if($row.Transport -ceq 'HTTP' -and ($row.Address -ceq '*' -or $row.Port -ceq '5985' -or $row.Address -ieq ('IP:'+$Selection.LocalAddress))){throw 'Existing HTTP5985, wildcard or selected listener conflicts; existing listeners are never changed.'}}
}
function Assert-WelaListenerCreated {
    param($Listener,$Selection)
    $expected=@{Address=('IP:'+$Selection.LocalAddress);Transport='HTTP';Port='5985';Hostname='';Enabled='true';URLPrefix='wsman';CertificateThumbprint=''}
    foreach($name in $expected.Keys){if($Listener.$name -isnot [string] -or $Listener.$name -cne $expected[$name]){throw "Created listener $name differs from the fixed selection."}}
    if($Listener.PolicyOwned -isnot [bool] -or $Listener.PolicyOwned -or $Listener.ListeningOn.Count -ne 1 -or $Listener.ListeningOn[0] -cne $Selection.LocalAddress){throw 'Created listener must be local and listen on exactly the selected IPv4 address.'}
}
function Get-WelaListenerSources {
    $sources=[ordered]@{}
    foreach($name in @('WELA.ps1','scripts/WecListener.ps1','scripts/WecListenerWorker.ps1','scripts/WecListenerPipeNative.cs','scripts/WefArrival.ps1','scripts/WecUpdate.ps1','scripts/ChannelRead.ps1','scripts/ChannelReadNative.cs','scripts/FirewallLoggingRecovery.ps1','modules/WefSubscriptions.psm1','modules/AuditProfiles.psm1','scripts/CustomAuditProfiles.ps1')){$sources[$name]=(Get-FileHash -LiteralPath (Join-Path $script:ScriptRoot $name) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()}
    Get-WelaListenerKey $sources
}
function Get-WelaListenerReaderKey {
    param($Reader)
    Get-WelaListenerKey ([ordered]@{Computer=$Reader.Computer;UserSid=$Reader.UserSid;UserName=$Reader.UserName;AuthenticationId=$Reader.AuthenticationId;GroupSids=$Reader.GroupSids;GroupCount=$Reader.GroupCount;PrivilegeCount=$Reader.PrivilegeCount;ElevatedAdministrator=$Reader.ElevatedAdministrator;TokenType=$Reader.TokenType;Impersonation=$Reader.Impersonation})
}
function Read-WelaListenerPolicy {
    # Refuse policy-owned WinRM settings; observe both native registry views without writing keys.
    $observations=@()
    foreach($view in @([Microsoft.Win32.RegistryView]::Registry64,[Microsoft.Win32.RegistryView]::Registry32)){
        $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$view)
        try {
            $queue=@('SOFTWARE\Policies\Microsoft\Windows\WinRM');$visited=0
            while($queue.Count){$path=$queue[0];$queue=@($queue|Select-Object -Skip 1);$visited++;if($visited -gt 32){throw 'WinRM policy key bound exceeded.'};$key=$base.OpenSubKey($path,$false)
                try{if($null -eq $key){$observations+=[pscustomobject]@{View=[string]$view;Path=$path;Exists=$false};continue};if($key.ValueCount){throw 'Policy-owned WinRM settings require manual review; no policy is overwritten.'};$children=@($key.GetSubKeyNames()|Sort-Object);$observations+=[pscustomobject]@{View=[string]$view;Path=$path;Exists=$true;Children=$children};foreach($child in $children){$queue+=($path+'\'+$child)}}finally{if($key){$key.Dispose()}}
            }
        }finally{$base.Dispose()}
    }
    Get-WelaListenerKey $observations
}
function Read-WelaListenerWinrm {
    $values=@(Microsoft.WSMan.Management\Get-WSManInstance -ResourceURI 'http://schemas.microsoft.com/wbem/wsman/1/config' -ErrorAction Stop)
    if($values.Count -ne 1 -or -not $values[0].OuterXml -or $values[0].OuterXml.Length -gt 262144){throw 'WinRM configuration is missing, ambiguous or oversized.'}
    $doc=Read-WelaWefXml ([string]$values[0].OuterXml)
    if($doc.DocumentElement.LocalName -cne 'Config' -or $doc.DocumentElement.NamespaceURI -cne 'http://schemas.microsoft.com/wbem/wsman/1/config'){throw 'Unexpected native WinRM configuration.'}
    [string]$doc.OuterXml
}
function Get-WelaListenerLocalState {
    $reader=Get-WelaChannelReader
    if(-not $reader.ElevatedAdministrator){throw 'The actual non-impersonated elevated administrator is required.'}
    $services=@(Get-Service -Name WinRM,Winmgmt,BFE,MpsSvc -ErrorAction Stop|Sort-Object Name|ForEach-Object {[pscustomobject]@{Name=$_.Name;Status=[string]$_.Status}})
    if($services.Count -ne 4 -or @($services|Where-Object Status -cne 'Running').Count){throw 'WinRM, Winmgmt, BFE and MpsSvc must already be running; no service is started.'}
    $hostState=Get-WelaChannelReadHost
    if($hostState.ProductType -ne 3 -or $hostState.DomainRole -notin @(2,3) -or $hostState.Build -notin @(20348,26100) -or $null -eq $hostState.UBR -or $hostState.UBR -lt 1){throw 'A reviewed patched native Server 2022/2025 standalone or member collector is required.'}
    $guid=(Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid;$parsed=[guid]::Empty
    if($guid -isnot [string] -or -not [guid]::TryParse($guid,[ref]$parsed) -or $parsed -eq [guid]::Empty){throw 'Actual machine identity is unavailable.'}
    $nativeServices=@(Get-CimInstance Win32_Service -Filter "Name='WinRM' OR Name='Wecsvc' OR Name='Winmgmt' OR Name='BFE' OR Name='MpsSvc'" -ErrorAction Stop|Sort-Object Name|Select-Object Name,State,StartMode)
    if($nativeServices.Count -ne 5 -or @($nativeServices|Where-Object {$_.State -notin @('Running','Stopped') -or $_.StartMode -notin @('Auto','Manual','Disabled')}).Count){throw 'Complete stable collector service observations are required.'}
    $addresses=@(NetTCPIP\Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop|Sort-Object InterfaceIndex,IPAddress|Select-Object IPAddress,InterfaceIndex,PrefixLength,PrefixOrigin,SuffixOrigin,AddressState,SkipAsSource)
    if($addresses.Count -lt 1 -or $addresses.Count -gt 128){throw 'Assigned address inventory is incomplete or excessive.'}
    $state=[pscustomobject][ordered]@{Host=$hostState;MachineGuid=$parsed.ToString();Reader=$reader;Services=$nativeServices;Addresses=$addresses;Policy=Read-WelaListenerPolicy;WinrmXml=Read-WelaListenerWinrm;Listeners=@(Read-WelaListenerInventory)}
    if((Get-WelaListenerKey (Get-WelaChannelReader)) -cne (Get-WelaListenerKey $reader)){throw 'Actual token changed during native observations.'}
    $state
}
function Get-WelaListenerState {
    $local=Get-WelaListenerLocalState;$native=Get-WelaFirewallRecoveryNativeSources;$profiles=@();$digests=@()
    foreach($store in @('PersistentStore','ActiveStore')){
        $rows=@(NetSecurity\Get-NetFirewallProfile -PolicyStore $store -ErrorAction Stop|Sort-Object Name)
        if($rows.Count -ne 3){throw 'All three firewall profiles must be observed in both stores.'}
        foreach($row in $rows){$profiles+=[pscustomobject]@{Store=$store;Profile=ConvertTo-WelaFirewallRecoveryCim $row @('Status','StatusCode','PrimaryStatus','OperationalStatus','InstanceID','InstanceId')}}
        $digests+=@(Get-WelaFirewallRecoveryRuleDigest $store)
    }
    $engine=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell/v1.0/powershell.exe';$worker=Join-Path $PSScriptRoot 'WecListenerWorker.ps1'
    $cmd=Get-Command 'Microsoft.WSMan.Management\Get-WSManInstance' -CommandType Cmdlet -ErrorAction Stop;$assembly=$cmd.ImplementingType.Assembly.Location
    if(-not $assembly -or $cmd.ModuleName -cne 'Microsoft.WSMan.Management'){throw 'Native WSMan reader source is unavailable.'}
    [pscustomobject][ordered]@{Local=$local;Profiles=$profiles;Rules=$digests;NativeFirewall=$native;NativeReader=[ordered]@{Path=$assembly;Sha256=(Get-FileHash $assembly -Algorithm SHA256).Hash};Adapter=[ordered]@{ModulePath=[IO.Path]::Combine([Environment]::SystemDirectory,'WindowsPowerShell\v1.0\Modules');Engine=$engine;EngineSha256=(Get-FileHash $engine -Algorithm SHA256).Hash;Worker=$worker;WorkerSha256=(Get-FileHash $worker -Algorithm SHA256).Hash};Sources=Get-WelaListenerSources}
}
function Get-WelaListenerReviewKey {
    param($State,[switch]$ExcludeSelected,$Selection)
    $copy=Get-WelaListenerKey $State|ConvertFrom-Json
    $copy.Local.Reader.ProcessId=$null;$copy.Local.Reader.TokenId=$null;$copy.Local.Reader.ModifiedId=$null
    if($ExcludeSelected){$copy.Local.Listeners=@($copy.Local.Listeners|Where-Object {-not($_.Address -ceq ('IP:'+$Selection.LocalAddress) -and $_.Transport -ceq 'HTTP')})}
    Get-WelaListenerKey $copy
}
function Assert-WelaListenerSelectedHost {
    param($State,$Selection)
    if($State.Host.Computer.ToUpperInvariant() -cne $Selection.ComputerName -or @($State.Addresses|Where-Object {$_.IPAddress -ceq $Selection.LocalAddress -and [string]$_.AddressState -ceq 'Preferred'}).Count -ne 1){throw 'Selection must identify this actual computer and exactly one currently assigned Preferred IPv4 address.'}
}
function New-WelaListenerPayload {
    '<cfg:Listener xmlns:cfg="http://schemas.microsoft.com/wbem/wsman/1/config/listener"><cfg:Port>5985</cfg:Port><cfg:Hostname/><cfg:Enabled>true</cfg:Enabled><cfg:URLPrefix>wsman</cfg:URLPrefix><cfg:CertificateThumbprint/></cfg:Listener>'
}
function Assert-WelaListenerPlan {
    param($Plan)
    Assert-WelaArrivalObject $Plan @('SchemaVersion','Kind','Selection','StateKey','RecordedUtc')
    if(($Plan.SchemaVersion -isnot [int] -and $Plan.SchemaVersion -isnot [long]) -or $Plan.SchemaVersion -ne 1 -or $Plan.Kind -isnot [string] -or $Plan.Kind -cne 'WelaExactIpListenerPlan' -or $Plan.StateKey -isnot [string] -or -not $Plan.StateKey -or $Plan.StateKey.Length -gt 2097152){throw 'Unknown or mistyped listener plan.'}
    Assert-WelaArrivalObject $Plan.Selection @('ComputerName','LocalAddress');$selection=Get-WelaListenerSelection $Plan.Selection.ComputerName $Plan.Selection.LocalAddress
    if((Get-WelaListenerKey $selection) -cne (Get-WelaListenerKey $Plan.Selection)){throw 'Listener plan selection is not canonical.'};$null=ConvertTo-WelaArrivalUtc $Plan.RecordedUtc
}
function Get-WelaListenerWorkerContextKey {
    param($Local)
    $copy=Get-WelaListenerKey $Local|ConvertFrom-Json
    $copy.Reader=Get-WelaListenerReaderKey $Local.Reader
    Get-WelaListenerKey $copy
}
function Invoke-WelaListenerWorkerRequest {
    param([string]$RequestPath,[string]$RequestHash)
    $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaNative51ListenerCreate';Status='Refused';NativeCreateAttempted=$false;ProcessId=$PID;Engine=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName;EngineVersion=$PSVersionTable.PSVersion.ToString();ModulePath=[string]$env:PSModulePath;Reader=$null;Selection=$null;CreatedXml=$null;After=@();Diagnostic='';NativeHResult=$null}
    $held=$null
    try {
        if($PSVersionTable.PSVersion.Major -ne 5 -or $RequestHash -cnotmatch '^[a-f0-9]{64}$'){throw 'A hashed fixed native Windows PowerShell5.1 request is required.'}
        $file=Read-WelaWecUpdateFile $RequestPath;if($file.Hash -cne $RequestHash){throw 'Native request hash differs.'}
        $request=ConvertFrom-WelaArrivalJson $file.Text
        Assert-WelaArrivalObject $request @('SchemaVersion','Kind','Selection','ContextKey','Sources','EngineSha256','PayloadHash')
        if(($request.SchemaVersion -isnot [int] -and $request.SchemaVersion -isnot [long]) -or $request.SchemaVersion -ne 1 -or $request.Kind -isnot [string] -or $request.Kind -cne 'WelaNative51ListenerRequest' -or $request.ContextKey -isnot [string] -or $request.Sources -isnot [string] -or $request.EngineSha256 -isnot [string] -or $request.PayloadHash -isnot [string] -or $request.PayloadHash -cnotmatch '^[a-f0-9]{64}$'){throw 'Unknown or mistyped native request.'}
        Assert-WelaArrivalObject $request.Selection @('ComputerName','LocalAddress');$selection=Get-WelaListenerSelection $request.Selection.ComputerName $request.Selection.LocalAddress;$report.Selection=$selection
        $expectedEngine=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell/v1.0/powershell.exe'
        if($report.Engine -ine $expectedEngine -or (Get-FileHash $expectedEngine -Algorithm SHA256).Hash -cne $request.EngineSha256 -or (Get-WelaListenerSources) -cne $request.Sources){throw 'Native adapter engine or installed sources differ.'}
        $payloadPath=Join-Path (Split-Path $file.Path -Parent) 'native-payload.xml';$payload=Read-WelaWecUpdateFile $payloadPath 4096
        if($payload.Hash -cne $request.PayloadHash -or $payload.Text -cne (New-WelaListenerPayload)){throw 'Native listener payload is not the exact fixed XML.'}
        $held=[IO.File]::Open($payload.Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $local=Get-WelaListenerLocalState;$report.Reader=$local.Reader
        Assert-WelaListenerSelectedHost $local $selection;Assert-WelaListenerAbsent $local.Listeners $selection
        if((Get-WelaListenerWorkerContextKey $local) -cne $request.ContextKey -or (Read-WelaWecUpdateFile $RequestPath).Hash -cne $RequestHash -or (Read-WelaWecUpdateFile $payloadPath 4096).Hash -cne $request.PayloadHash -or (Get-WelaListenerSources) -cne $request.Sources){throw 'Fresh native adapter context, input or code differs.'}
        $report.NativeCreateAttempted=$true
        $created=@(Microsoft.WSMan.Management\New-WSManInstance -ResourceURI 'http://schemas.microsoft.com/wbem/wsman/1/config/listener' -SelectorSet @{Address=('IP:'+$selection.LocalAddress);Transport='HTTP'} -FilePath $payload.Path -ErrorAction Stop)
        if($created.Count -ne 1 -or -not $created[0].OuterXml -or $created[0].OuterXml.Length -gt 32768){throw 'Native create response is incomplete or excessive.'};$report.CreatedXml=[string]$created[0].OuterXml
        $after=Get-WelaListenerLocalState;$report.After=$after.Listeners
        $chosen=@($after.Listeners|Where-Object {$_.Address -ceq ('IP:'+$selection.LocalAddress) -and $_.Transport -ceq 'HTTP'})
        if($chosen.Count -ne 1){throw 'Native creation did not produce exactly one selected listener.'};Assert-WelaListenerCreated $chosen[0] $selection
        $after.Listeners=@($after.Listeners|Where-Object {-not($_.Address -ceq ('IP:'+$selection.LocalAddress) -and $_.Transport -ceq 'HTTP')})
        if((Get-WelaListenerWorkerContextKey $after) -cne $request.ContextKey -or (Get-WelaListenerKey $after.Reader) -cne (Get-WelaListenerKey $local.Reader) -or (Get-WelaListenerSources) -cne $request.Sources){throw 'Native adapter context, token, other listeners or source changed during creation.'}
        $report.Status='Created'
    }catch{$report.Status=if($report.NativeCreateAttempted){'CreateAttemptedUnverified'}else{'Refused'};$report.Diagnostic=$_.Exception.Message;$report.NativeHResult=$_.Exception.HResult;try{$report.After=@(Read-WelaListenerInventory)}catch{}}
    finally{if($held){$held.Dispose()}}
    $report
}
function Initialize-WelaListenerPipe {
    $path=Join-Path $PSScriptRoot 'WecListenerPipeNative.cs';$bytes=[IO.File]::ReadAllBytes($path)
    if($bytes.Length -gt 65536){throw 'Listener pipe source exceeds its bound.'};$hash=Get-WelaArrivalHash $bytes
    if(-not('Wela.ListenerPipe.Bounded' -as [type])){
        $source=[Text.UTF8Encoding]::new($false,$true).GetString($bytes).TrimStart([char]0xfeff)
        if([regex]::Matches($source,'__WELA_SOURCE_SHA256__').Count -ne 1){throw 'Listener pipe source marker is missing or ambiguous.'}
        Add-Type -TypeDefinition $source.Replace('__WELA_SOURCE_SHA256__',$hash) -ErrorAction Stop
    }
    if([Wela.ListenerPipe.Bounded]::SourceSha256 -cne $hash){throw 'Loaded listener pipe helper differs from its source.'}
}
function Close-WelaListenerAdapterProcess {
    param($Process,$Result)
    # Cleanup must never discard Started=true after a possibly mutating child ran.
    if($Result.Started){
        $exited=$false
        try{$exited=$Process.HasExited}catch{$Result.Diagnostic+=' Adapter exit observation failed: '+$_.Exception.Message}
        if(-not $exited){
            try{$Process.Kill()}catch{$Result.Diagnostic+=' Adapter termination request failed: '+$_.Exception.Message}
            try{$exited=$Process.WaitForExit(5000)}catch{$Result.Diagnostic+=' Adapter termination wait failed: '+$_.Exception.Message}
        }
        $Result.TerminationConfirmed=[bool]$exited
        if(-not $exited){$Result.Diagnostic+=' Adapter termination is unconfirmed.'}
    }
    try{$Process.Dispose()}catch{$Result.Diagnostic+=' Adapter resource cleanup failed: '+$_.Exception.Message}
}
function Assert-WelaListenerAdapterReceipt {
    param($Receipt,$State,[int]$ProcessId,[int]$ExitCode)
        Assert-WelaArrivalObject $receipt @('SchemaVersion','Kind','Status','NativeCreateAttempted','ProcessId','Engine','EngineVersion','ModulePath','Reader','Selection','CreatedXml','After','Diagnostic','NativeHResult')
        if(($receipt.SchemaVersion -isnot [int] -and $receipt.SchemaVersion -isnot [long]) -or $receipt.SchemaVersion -ne 1 -or $receipt.Kind -isnot [string] -or $receipt.Kind -cne 'WelaNative51ListenerCreate' -or $receipt.NativeCreateAttempted -isnot [bool] -or ($receipt.ProcessId -isnot [int] -and $receipt.ProcessId -isnot [long]) -or $receipt.ProcessId -ne $ProcessId -or $receipt.Engine -isnot [string] -or $receipt.Engine -ine $State.Adapter.Engine -or $receipt.ModulePath -isnot [string] -or $receipt.ModulePath -cne $State.Adapter.ModulePath -or $receipt.EngineVersion -isnot [string] -or $receipt.EngineVersion -cnotmatch '^5\.1\.[0-9]+\.[0-9]+$' -or $receipt.Status -isnot [string] -or $receipt.Status -cnotin @('Created','Refused','CreateAttemptedUnverified') -or $receipt.Diagnostic -isnot [string]){throw 'Native adapter receipt has inconsistent identity or status.'}
        if($receipt.Reader -and (Get-WelaListenerReaderKey $receipt.Reader) -cne (Get-WelaListenerReaderKey $State.Local.Reader)){throw 'Native adapter did not run under the reviewed actual account/logon.'}
        if($receipt.Status -ceq 'Created' -and (-not $receipt.Reader -or -not $receipt.NativeCreateAttempted -or $ExitCode -ne 0 -or $receipt.Diagnostic)){throw 'Native adapter success receipt is incomplete.'}
}
function Start-WelaListenerAdapter {
    param($State,[string]$RequestPath,[string]$RequestHash)
    foreach($path in @($State.Adapter.Engine,$State.Adapter.Worker,$RequestPath)){if($path.Contains('"') -or $path.EndsWith('\') -or $path -match '[\x00-\x1f]'){throw 'Unsupported native adapter path.'}}
    $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$State.Adapter.Engine
    $info.Arguments='-NoLogo -NoProfile -NonInteractive -File "'+$State.Adapter.Worker+'" -RequestPath "'+$RequestPath+'" -RequestHash '+$RequestHash
    $info.EnvironmentVariables['PSModulePath']=$State.Adapter.ModulePath
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true;$info.StandardOutputEncoding=[Text.UTF8Encoding]::new($false);$info.StandardErrorEncoding=[Text.UTF8Encoding]::new($false)
    Initialize-WelaListenerPipe
    $result=[pscustomobject][ordered]@{Started=$false;ProcessId=$null;ExitCode=$null;TimedOut=$false;TerminationConfirmed=$false;Receipt=$null;Diagnostic=''};$process=[Diagnostics.Process]::new();$process.StartInfo=$info
    try {
        if(-not $process.Start()){throw 'Native listener adapter did not start.'};$result.Started=$true;$result.ProcessId=$process.Id
        $stdout=[Wela.ListenerPipe.Bounded]::Read($process.StandardOutput,524288);$stderr=[Wela.ListenerPipe.Bounded]::Read($process.StandardError,65536)
        if(-not $process.WaitForExit(45000)){$result.TimedOut=$true;throw 'Native listener adapter timed out; creation may have been attempted.'}
        $result.ExitCode=$process.ExitCode
        if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout,$stderr),5000)){throw 'Native listener adapter output drain timed out.'}
        $text=$stdout.Result;$errorText=$stderr.Result
        if($errorText -or $text.Length -gt 524288){throw 'Native adapter output is incomplete, excessive or contains errors.'}
        $receipt=ConvertFrom-WelaArrivalJson $text
        Assert-WelaListenerAdapterReceipt $receipt $State $result.ProcessId $result.ExitCode
        $result.Receipt=$receipt
    }catch{$result.Diagnostic=$_.Exception.Message}
    finally{Close-WelaListenerAdapterProcess $process $result}
    $result
}
function Invoke-WelaWecListener {
    param([ValidateSet('Plan','Apply')][string]$Action='Plan',[string]$ComputerName,[string]$LocalAddress,[string]$PlanPath,[string]$PlanHash,[string]$OutputPath)
    if($args.Count){throw 'Unknown listener arguments are not supported.'}
    if($Action -eq 'Plan'){
        if(-not $ComputerName -or -not $LocalAddress -or -not $OutputPath -or $PSBoundParameters.ContainsKey('PlanPath') -or $PSBoundParameters.ContainsKey('PlanHash')){throw 'Plan requires the actual computer, assigned IPv4 and new output only.'}
        $selection=Get-WelaListenerSelection $ComputerName $LocalAddress;$reviewedFile=$null
    }else{
        if(-not $PlanPath -or $PlanHash -cnotmatch '^[a-fA-F0-9]{64}$' -or -not $OutputPath -or $PSBoundParameters.ContainsKey('ComputerName') -or $PSBoundParameters.ContainsKey('LocalAddress')){throw 'Apply requires only a reviewed plan, SHA256 and new output.'}
        $PlanHash=$PlanHash.ToLowerInvariant();$reviewedFile=Read-WelaWecUpdateFile $PlanPath
    }
    $source=if($reviewedFile){$reviewedFile.Path}else{Join-Path $script:ScriptRoot 'WELA.ps1'};$output=New-WelaArrivalOutput $OutputPath $source
    $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaExactIpListener';Action=$Action;Status='Refused';ExitCode=1;OutputPath=$output;PlanHash=$null;AdapterStarted=$false;NativeCreateAttempted=$null;Adapter=$null;Artifacts=@();Diagnostic='';ReadyRuleCredit=0;ServiceChanges=0;AuthenticationChanges=0;FirewallChanges=0;Scope='One new exact assigned-IPv4 HTTP5985/wsman listener through a fixed native Windows PowerShell5.1 adapter. Existing WinRM endpoints may use it. No remote connection, WEF delivery, packet acceptance, retention or Sigma proof. Sysmon excluded.'}
    try {
        $state=Get-WelaListenerState;$key=Get-WelaListenerReviewKey $state;$tokenKey=Get-WelaListenerKey $state.Local.Reader
        if($Action -eq 'Apply'){
            if($reviewedFile.Hash -cne $PlanHash){throw 'Reviewed listener plan hash differs.'};$plan=ConvertFrom-WelaArrivalJson $reviewedFile.Text;Assert-WelaListenerPlan $plan
            if($plan.StateKey -cne $key){throw 'Reviewed host/operator/code/listener/WinRM/firewall state differs.'};$selection=Get-WelaListenerSelection $plan.Selection.ComputerName $plan.Selection.LocalAddress;$report.PlanHash=$PlanHash
        }
        Assert-WelaListenerSelectedHost $state.Local $selection;Assert-WelaListenerAbsent $state.Local.Listeners $selection
        if($Action -eq 'Plan'){
            $plan=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaExactIpListenerPlan';Selection=$selection;StateKey=$key;RecordedUtc=[DateTime]::UtcNow.ToString('o')};Assert-WelaListenerPlan $plan
            $fresh=Get-WelaListenerState;if((Get-WelaListenerReviewKey $fresh) -cne $key -or (Get-WelaListenerKey $fresh.Local.Reader) -cne $tokenKey){throw 'Context changed during listener planning.'};Assert-WelaListenerAbsent $fresh.Local.Listeners $selection
            $artifact=Write-WelaWecUpdateArtifact $output 'plan.json' ($plan|ConvertTo-Json -Depth 24);$report.Artifacts+=$artifact;$report.PlanHash=$artifact.Sha256;$report.Status='ReviewRequired';$report.ExitCode=0
        }else{
            $report.Artifacts+=Write-WelaWecUpdateArtifact $output 'reviewed-plan.json' $reviewedFile.Text
            $report.Artifacts+=Write-WelaWecUpdateArtifact $output 'before-create.json' ([ordered]@{Status='Pending';PlanHash=$PlanHash;Selection=$selection;State=$state;RecordedUtc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Depth 24)
            $payload=Write-WelaWecUpdateArtifact $output 'native-payload.xml' (New-WelaListenerPayload);$report.Artifacts+=$payload
            $request=[ordered]@{SchemaVersion=1;Kind='WelaNative51ListenerRequest';Selection=$selection;ContextKey=(Get-WelaListenerWorkerContextKey $state.Local);Sources=$state.Sources;EngineSha256=$state.Adapter.EngineSha256;PayloadHash=$payload.Sha256}
            $artifact=Write-WelaWecUpdateArtifact $output 'native-request.json' ($request|ConvertTo-Json -Depth 24);$report.Artifacts+=$artifact
            $fresh=Get-WelaListenerState;if((Get-WelaListenerReviewKey $fresh) -cne $key -or (Get-WelaListenerKey $fresh.Local.Reader) -cne $tokenKey -or (Read-WelaWecUpdateFile $PlanPath).Hash -cne $PlanHash){throw 'Plan or actual state changed immediately before creation.'};Assert-WelaListenerAbsent $fresh.Local.Listeners $selection
            $adapter=Start-WelaListenerAdapter $state (Join-Path $output 'native-request.json') $artifact.Sha256;$report.Adapter=$adapter;$report.AdapterStarted=$adapter.Started
            if($adapter.Receipt){$report.NativeCreateAttempted=$adapter.Receipt.NativeCreateAttempted}
            $report.Artifacts+=Write-WelaWecUpdateArtifact $output 'adapter-receipt.json' ($adapter|ConvertTo-Json -Depth 24)
            $after=Get-WelaListenerState;$report.Artifacts+=Write-WelaWecUpdateArtifact $output 'after-state.json' ($after|ConvertTo-Json -Depth 24)
            if($adapter.Diagnostic -or -not $adapter.Receipt -or $adapter.Receipt.Status -cne 'Created' -or -not $adapter.Receipt.NativeCreateAttempted -or (Get-WelaListenerKey $adapter.Receipt.Selection) -cne (Get-WelaListenerKey $selection)){throw ('Native creation is unverified: '+$adapter.Diagnostic+' '+$adapter.Receipt.Diagnostic)}
            $selected=@($after.Local.Listeners|Where-Object {$_.Address -ceq ('IP:'+$selection.LocalAddress) -and $_.Transport -ceq 'HTTP'});if($selected.Count -ne 1){throw 'Expected exactly one created listener.'};Assert-WelaListenerCreated $selected[0] $selection
            if((Get-WelaListenerReviewKey $after -ExcludeSelected -Selection $selection) -cne $key -or (Get-WelaListenerKey $after.Local.Reader) -cne $tokenKey -or (Read-WelaWecUpdateFile $PlanPath).Hash -cne $PlanHash){throw 'Host/token/code/plan, other listeners, WinRM or firewall configuration changed during creation.'}
            $report.Status='CreatedAndVerified';$report.ExitCode=0
        }
    }catch{
        $report.Status=if($report.AdapterStarted -and ($null -eq $report.NativeCreateAttempted -or $report.NativeCreateAttempted)){'CreateAttemptedUnverified'}else{'Refused'};$report.Diagnostic=$_.Exception.Message
        if($report.AdapterStarted -and -not @($report.Artifacts|Where-Object Name -eq 'after-state.json').Count){try{$report.Artifacts+=Write-WelaWecUpdateArtifact $output 'after-state.json' ((Get-WelaListenerState)|ConvertTo-Json -Depth 24)}catch{}}
    }
    $null=Write-WelaWecUpdateArtifact $output 'manifest.json' ($report|ConvertTo-Json -Depth 24);$report
}
