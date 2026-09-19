$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/AuditProfiles.psm1') -Force
. (Join-Path $repo 'scripts/ControlApplicability.ps1')
. (Join-Path $repo 'scripts/NativeValidation.ps1')
. (Join-Path $repo 'scripts/WefArrival.ps1')
. (Join-Path $PSScriptRoot 'fixtures/WefArrival.Fixture.ps1')
$script:checks=0
function Assert($Value,[string]$Message){if(-not $Value){throw "FAIL: $Message"};$script:checks++}
function Reject([scriptblock]$Code,[string]$Pattern){$message='';try{& $Code|Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern; got $message"}
function Clone($Value){ConvertFrom-WelaArrivalJson ($Value|ConvertTo-Json -Depth 24)}
function Save($Path,$Value){[IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 24),[Text.UTF8Encoding]::new($false))}
function Update-Source($Directory,$Name,$Value) {
    Save (Join-Path $Directory $Name) $Value
    $m=ConvertFrom-WelaArrivalJson (Get-Content (Join-Path $Directory 'manifest.json') -Raw)
    ($m.Artifacts|Where-Object path -eq $Name).sha256=(Get-FileHash (Join-Path $Directory $Name)).Hash.ToLowerInvariant()
    switch($Name){'before-state.json'{$m.BeforeState=$Value};'after-state.json'{$m.AfterState=$Value};'process.json'{$m.Process=$Value}}
    Save (Join-Path $Directory 'manifest.json') $m
}
function Start-WelaProbeProcess {throw 'Forbidden process launch'}
function Invoke-WelaNative {throw 'Forbidden native mutation'}
function Set-ItemProperty {throw 'Forbidden registry mutation'}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-arrival-tests-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $temp
try {
    $fixture=New-WelaArrivalFixture (Join-Path $temp 'source')
    $source=Import-WelaArrivalProbe $fixture.Directory
    Assert ($source.Event.Computer -eq 'source01.lab.test' -and $source.Files.Count -eq 5) 'Completed native-shaped source bundle validates with all hashes'
    $fractional=New-WelaArrivalFixture (Join-Path $temp 'fractional-zeroes') -Timestamp ([datetime]::SpecifyKind([datetime]'2025-01-02T03:04:05.1234500',[DateTimeKind]::Utc))
    $fractionalSource=Import-WelaArrivalProbe $fractional.Directory
    Assert ($fractionalSource.Manifest.BeforeState.capturedAtUtc -is [string] -and $fractionalSource.Manifest.BeforeState.capturedAtUtc.EndsWith('.1234500Z')) 'Fixture retains fractional timestamp zeroes as strings in embedded metadata'
    Assert ($fractionalSource.Files.Count -eq 5) 'Deterministic fractional-zero fixture passes the unchanged strict bundle importer'
    foreach($case in @('hash','extra','duplicate-json','bad-status','embedded','typed','missing-mask','source-drift','time','process-command','unknown-field','bad-kind','duplicate-artifact')) {
        $dir=Join-Path $temp $case;Copy-Item $fixture.Directory $dir -Recurse
        $m=Clone $fixture.Manifest
        switch($case){
            'hash'{Add-Content (Join-Path $dir 'event.xml') 'tampered'}
            'extra'{Set-Content (Join-Path $dir 'extra.txt') 'extra'}
            'duplicate-json'{$text=ConvertTo-Json -InputObject $m -Depth 24 -Compress;$t=$text.Replace('"SchemaVersion":1,','"SchemaVersion":1,"SchemaVersion":1,');Assert ($t -cne $text) 'Duplicate-key fixture changed input';[IO.File]::WriteAllText((Join-Path $dir 'manifest.json'),$t)}
            'bad-status'{$m.Status='Unverified';Save (Join-Path $dir 'manifest.json') $m}
            'embedded'{$m.BeforeState.context.computer='different';Save (Join-Path $dir 'manifest.json') $m}
            'typed'{$m.BeforeState.auditPrecedence.Value='1';Update-Source $dir 'before-state.json' $m.BeforeState}
            'missing-mask'{$m.BeforeState.auditPolicies.PSObject.Properties.Remove(@($m.BeforeState.auditPolicies.PSObject.Properties.Name)[0]);Update-Source $dir 'before-state.json' $m.BeforeState}
            'source-drift'{$m.AfterState.auditPolicies.'0CCE922B-69AE-11D9-BED3-505054503030'=3;Update-Source $dir 'after-state.json' $m.AfterState}
            'time'{$m.Process.StartedUtc=[DateTime]::UtcNow.AddDays(1).ToString('o');Update-Source $dir 'process.json' $m.Process}
            'process-command'{$m.Process.Arguments='/c whoami';Update-Source $dir 'process.json' $m.Process}
            'unknown-field'{$m|Add-Member NoteProperty Ready $true;Save (Join-Path $dir 'manifest.json') $m}
            'bad-kind'{$m.Kind='WelaNativeRuleEvidence';Save (Join-Path $dir 'manifest.json') $m}
            'duplicate-artifact'{$m.Artifacts[1]=$m.Artifacts[0];Save (Join-Path $dir 'manifest.json') $m}
        }
        Reject {Import-WelaArrivalProbe $dir} 'hash|five|Duplicate|successful|differs|DWORD|59-subcategory|drifted|timestamps|fixed|Unexpected'
    }
    foreach($text in @('{"x":1,"X":2}','{x:1}','{"x":1,}',"{'x':1}",'{"x":NaN}')) {Reject {ConvertFrom-WelaArrivalJson $text} 'JSON|Duplicate|strict'}
    $rendered=$fixture.Xml.Replace('</Event>','<RenderingInfo Culture="en-US"><Message>Localized &lt;script&gt; text</Message></RenderingInfo></Event>')
    Assert ((Read-WelaArrivalEvent $rendered).Key -ceq $source.Event.Key) 'RenderingInfo does not change original event identity'
    Assert ((Read-WelaArrivalEvent ($fixture.Xml.Replace('>LAB</Data>','>   </Data>'))).Key -cne (Read-WelaArrivalEvent ($fixture.Xml.Replace('>LAB</Data>','></Data>'))).Key) 'Whitespace-only original payload values remain distinct from empty values'
    foreach($change in @(@('source01.lab.test','wrong.lab.test'),@('0x7b','0x7c'),@('S-1-16-16384','S-1-16-8192'),@('%%1936','%%1937'),@('<EventRecordID>100','<EventRecordID>101'),@('<Version>2','<Version>1'),@('WELA_PROBE_0123456789abcdef0123456789abcdef','WELA_PROBE_1123456789abcdef0123456789abcdef'))) {
        Assert ((Read-WelaArrivalEvent ($fixture.Xml.Replace($change[0],$change[1]))).Key -cne $source.Event.Key) "Original event mutation stays unmatched: $($change[0])"
    }
    foreach($xml in @($fixture.Xml.Replace('</Event>','<UserData/></Event>'),$fixture.Xml.Replace('</Event>','<System/></Event>'),('<!DOCTYPE Event [<!ENTITY a SYSTEM "file:///etc/passwd">]>'+$fixture.Xml))) {Reject {Read-WelaArrivalEvent $xml} 'System|DTD'}
    $script:collector=[pscustomobject]@{CapturedUtc=[DateTime]::UtcNow.ToString('o');Computer='collector01';Host=$fixture.Host;Reader=[pscustomobject]@{UserSid='S-1-5-18';Name='NT AUTHORITY\SYSTEM';AuthenticationType='NTLM';IsSystem=$true;ImpersonationLevel='None';GroupSids=@('S-1-5-32-544')};Channel=[pscustomobject]@{Name='ForwardedEvents';Enabled=$true;LogMode='Circular';MaximumSizeInBytes=20971520;SecurityDescriptor='O:BAG:BAD:(A;;0x1;;;SY)';LogFilePath='C:\Windows\System32\winevt\Logs\ForwardedEvents.evtx'}}
    # Exercise the real query adapter with native-shaped records and a captured query.
    & {
        $script:disposed=0;$script:queryArgs=$null;$script:queryCase='records'
        function Get-WinEvent {
            param($LogName,$FilterXPath,$MaxEvents,$ErrorAction)
            $script:queryArgs=@{LogName=$LogName;FilterXPath=$FilterXPath;MaxEvents=$MaxEvents}
            if($queryCase -eq 'denied'){throw 'native query denied'}
            if($queryCase -eq 'empty') {Write-Error -Message 'No events' -ErrorId NoMatchingEventsFound -Category ObjectNotFound;return}
            foreach($i in 1..2){$r=[pscustomobject]@{Payload=$rendered};$r|Add-Member ScriptMethod ToXml {if($script:queryCase -eq 'xml-failed'){throw 'render failed'};$this.Payload};$r|Add-Member ScriptMethod Dispose {$script:disposed++};$r}
        }
        $batch=Read-WelaArrivalEvents $source.Event -MaximumEvents 2
        Assert ($batch.Capped -and $batch.Xml.Count -eq 2 -and $disposed -eq 2) 'Native cap is explicit and every native record is disposed'
        Assert ($queryArgs.LogName -ceq 'ForwardedEvents' -and $queryArgs.FilterXPath -match "Computer='source01.lab.test'" -and $queryArgs.FilterXPath -match 'EventID=4688' -and $queryArgs.FilterXPath -match 'TimeCreated' -and $queryArgs.MaxEvents -eq 2) 'Native query targets physical collector log with exact source identity and bounded original event time'
        $script:queryCase='empty';$batch=Read-WelaArrivalEvents $source.Event
        Assert ($batch.Xml.Count -eq 0 -and -not $batch.Capped) 'No native matches differs from denied query'
        $script:queryCase='denied';Reject {Read-WelaArrivalEvents $source.Event} 'denied'
        $script:queryCase='xml-failed';$script:disposed=0;Reject {Read-WelaArrivalEvents $source.Event} 'render failed'
        Assert ($disposed -eq 2) 'XML conversion failure still releases all native record handles'
    }
    $script:reads=0;$script:scenario='match'
    function Get-WelaArrivalCollector {$script:reads++;if($scenario -eq 'context-denied'){throw 'context denied'};$value=Clone $script:collector;if($reads -gt 1 -and $scenario -eq 'reader-drift'){$value.Reader.UserSid='S-1-5-19'};if($reads -gt 1 -and $scenario -eq 'channel-drift'){$value.Channel.Enabled=$false};$value}
    function Read-WelaArrivalEvents {
        param($SourceEvent)
        if($scenario -eq 'denied'){throw 'ForwardedEvents denied'}
        if($scenario -eq 'source-race'){Add-Content (Join-Path $fixture.Directory 'event.xml') 'race'}
        $rows=switch($scenario){'missing'{@()};'duplicate'{@($rendered,$rendered)};'wrong'{@($rendered.Replace('S-1-16-16384','S-1-16-8192'))};default{@($rendered)}}
        [pscustomobject]@{Channel='ForwardedEvents';Query='fixed synthetic query';StartedUtc=[DateTime]::UtcNow.ToString('o');CompletedUtc=[DateTime]::UtcNow.ToString('o');Xml=@($rows);Capped=($scenario -eq 'cap');MaximumEvents=512}
    }
    foreach($case in @('match','missing','duplicate','wrong','denied','cap','reader-drift','channel-drift','context-denied','source-race')) {
        $script:scenario=$case;$script:reads=0;$output=Join-Path $temp ('out-'+$case)
        $result=Invoke-WelaWefArrival $fixture.Directory $output
        Assert (Test-Path (Join-Path $output 'manifest.json')) "Final or failed evidence manifest retained: $case"
        Assert ($result.PolicyChanges -eq 0 -and $result.ReadyRuleCredit -eq 0 -and $result.SubscriptionAttribution -eq 'Not established' -and $result.TransmissionLatency -eq 'Not measured') 'Presence never becomes policy, subscription, latency or rule evidence'
        if($case -eq 'match'){
            Assert ($result.ExitCode -eq 0 -and $result.Status -eq 'PresentOnCollector' -and $result.ExactMatches -eq 1) 'One exact event establishes local presence only'
            Assert ((Get-Content (Join-Path $output 'collector-event.xml') -Raw) -ceq $rendered) 'Raw native-shaped collector XML including rendering is retained'
            foreach($artifact in $result.Artifacts){Assert ((Get-FileHash (Join-Path $output $artifact.Name)).Hash.ToLowerInvariant() -ceq $artifact.Sha256) 'Evidence fingerprints match written bytes'}
        }else{Assert ($result.ExitCode -eq 1 -and $result.Status -eq 'Unverified' -and $result.Diagnostic) "Incomplete collection stays unverified: $case"}
        if($case -ne 'context-denied'){Assert ($null -ne $result.CollectorAfter) 'Final actual collector observation retained even on query failure'}
        if($case -eq 'duplicate'){Assert (@($result.Artifacts|Where-Object Name -like 'collector-duplicate*').Count -eq 2) 'Duplicate diagnostic XML is retained without choosing an arrival'}
        if($case -eq 'source-race'){[IO.File]::WriteAllText((Join-Path $fixture.Directory 'event.xml'),$fixture.Xml,[Text.UTF8Encoding]::new($false))}
    }
    $script:scenario='match';$script:reads=0
    Push-Location $temp
    try {$r=Invoke-WelaWefArrival './source' './relative-output';Assert ($r.OutputPath -eq (Join-Path $temp 'relative-output')) 'Relative output follows PowerShell location'} finally {Pop-Location}
    Reject {Invoke-WelaWefArrival $fixture.Directory (Join-Path $temp 'relative-output')} 'new directory'
    Reject {Invoke-WelaWefArrival $fixture.Directory (Join-Path $fixture.Directory 'nested')} 'outside'
    $link=Join-Path $temp 'link';$null=New-Item -ItemType SymbolicLink -Path $link -Target $fixture.Directory
    Reject {Import-WelaArrivalProbe $link} 'reparse'
    Reject {New-WelaArrivalOutput (Join-Path $link 'child') $fixture.Directory} 'reparse'
    Reject {Resolve-WelaArrivalPath 'HKLM:\test'} 'filesystem|drive'
    Reject {Resolve-WelaArrivalPath 'wild*path'} 'exact paths'
    $errors=$null;[void][Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'WELA.ps1'),[ref]$null,[ref]$errors)
    Assert ($errors.Count -eq 0) 'Public CLI parses'
    foreach($arguments in @(@('configure','-Profile','wela','-ArrivalProbePath','x'),@('wef-arrival','-Auto'),@('wef-arrival','-Role','Client'),@('wef-arrival','-DryRun'))) {
        $saved=$ErrorActionPreference;$ErrorActionPreference='Continue'
        try {$text=& (Get-Process -Id $PID).Path -NoProfile -File (Join-Path $repo 'WELA.ps1') @arguments 2>&1;$code=$LASTEXITCODE} finally {$ErrorActionPreference=$saved}
        Assert ($code -ne 0 -and ($text -join ' ') -match 'Arrival options require|wef-arrival accepts only') 'Early public guard rejects unrelated mutation options'
    }
    $global:LASTEXITCODE=0
    Write-Host "PASS: $script:checks WEF arrival assertions. Fixtures are synthetic; no actual forwarding is claimed."
} finally {Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}
