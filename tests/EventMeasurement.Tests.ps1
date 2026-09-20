$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'scripts/EvtxRecovery.ps1')
. (Join-Path $repo 'scripts/EventMeasurement.ps1')
$script:checks=0
function Assert($Value,[string]$Message){if(-not $Value){throw "FAIL: $Message"};$script:checks++}
function Reject([scriptblock]$Code,[string]$Pattern){$message='';try{& $Code|Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern; got $message"}
function Event([int]$Id=10,[string]$Payload='<EventData><Data Name="Value">owned &amp; exact</Data></EventData>',[string]$Channel='Security',[string]$Computer='HOST.lab.test') {
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/><EventID>4688</EventID><Version>2</Version><TimeCreated SystemTime="2025-01-02T03:04:05.1234500Z"/><EventRecordID>'+ $Id +'</EventRecordID><Channel>'+ $Channel +'</Channel><Computer>'+ $Computer +'</Computer></System>'+ $Payload +'</Event>'
}
function Delivery([int]$Id=10) {[pscustomobject]@{Xml=(Event $Id);BookmarkXml=('<BookmarkList><Bookmark Channel="Security" RecordId="'+$Id+'" IsCurrent="true"/></BookmarkList>');ElapsedSeconds=0.25}}
function Capture([array]$Events=@()) {[pscustomobject]@{Status='WindowComplete';NativeError=0;Diagnostic='';StartedUtc='2025-01-02T03:04:05Z';CompletedUtc='2025-01-02T03:04:06Z';RegistrationSeconds=0.01;ElapsedSeconds=1;OutsideWindowCallbacks=0;BeforeWindowCallbacks=0;XmlUtf8Bytes=0;Events=$Events}}
function State {
    [pscustomobject]@{CapturedUtc='2025-01-02T03:04:05Z';Reader=[pscustomobject]@{Computer='HOST';SourceComputerNames=@('HOST','HOST.lab.test');HostKey='specific host context';Reader=[pscustomobject]@{Sid='S-1-5-18'}};Configuration=[pscustomobject]@{Name='Security';Type='Administrative';Enabled=$true;Mode='Circular';MaximumBytes=20971520;RegisteredPath='C:\Windows\System32\winevt\Logs\Security.evtx';SecurityDescriptor='specific SDDL';Providers=@('Microsoft-Windows-Security-Auditing')};Log=[pscustomobject]@{CreatedUtc='2025-01-01T00:00:00Z';OldestRecord=1;RecordCount=9;FileBytes=1048576;Full=$false}}
}
$script:stateReads=0;$script:drift='';$script:exportCalls=0;$script:reopen=@();$script:capture=Capture;$script:tamperPath=$null
function Get-WelaMeasurementState {
    $script:stateReads++;$s=State
    if ($script:stateReads -eq 3 -and $script:tamperPath) {[IO.File]::WriteAllBytes($script:tamperPath,[byte[]]@(1,2,3,4))}
    if($script:stateReads -gt 1){switch($script:drift){'reader'{$s.Reader.Reader.Sid='different'};'mode'{$s.Configuration.Mode='Retain'};'created'{$s.Log.CreatedUtc='different'};'clear'{$s.Log.RecordCount=0};'denied'{throw 'Access denied to channel'}}};$s
}
function New-WelaMeasurementObserver {
    $o=[pscustomobject]@{StartedUtc='2025-01-02T03:04:05Z';RegistrationSeconds=0.01}
    $o|Add-Member ScriptMethod Complete {return $script:capture};$o|Add-Member ScriptMethod Dispose {};return $o
}
function Export-WelaMeasurementEvtx {param($Channel,$Query,$Path);$script:exportCalls++;[IO.File]::WriteAllBytes($Path,[byte[]]@(69,86,84,88,1,2,3,4))}
function Read-WelaMeasurementEvtx {param($Path,$MaximumEvents);return ,$script:reopen}
function Invoke-WelaNative {throw 'Forbidden native configuration write'}
function Set-ItemProperty {throw 'Forbidden registry write'}
function Start-WelaProbeProcess {throw 'Forbidden product probe generation'}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-measurement-tests-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $temp
function Run([string]$Name,[switch]$Export) {$script:stateReads=0;Invoke-WelaEventMeasurement -Action Run -Channel Security -Seconds 1 -OutputPath (Join-Path $temp $Name) -ExportEvtx:$Export}
try {
    Add-Type -Path (Join-Path $repo 'scripts/EventMeasurementNative.cs') -ErrorAction Stop
    Assert ([bool]('Wela.EventMeasurementV1.Observer' -as [type])) 'Native callback implementation compiles without calling Windows APIs'
    Assert ((Get-WelaMeasurementCatalog).Channels.Count -eq 7) 'Seven exact reviewed local channels'
    foreach($bad in @('ForwardedEvents','Security*','Microsoft-Windows-DNSServer/Analytical','\\server\Security','Microsoft-Windows-Sysmon/Operational','security')) {Reject {Invoke-WelaEventMeasurement -Channel $bad} 'exact reviewed'}
    Assert ($script:stateReads -eq 0) 'Unsupported selection rejected before host reads'
    Reject {Invoke-WelaEventMeasurement -Channel Security -OutputPath $temp} 'require Run'
    Reject {Invoke-WelaEventMeasurement -Action Run -Channel Security} 'new private'
    Reject {Invoke-WelaEventMeasurement -Action Run -Channel Security -OutputPath $temp} 'already exists'
    foreach($alias in @('data.','data ','CON.txt','sample:stream','wild*')) {$raw=$temp+[IO.Path]::DirectorySeparatorChar+$alias;Assert ($raw.EndsWith($alias)) 'Alias fixture retains literal spelling before provider normalization';Reject {Resolve-WelaMeasurementPath $raw} 'path|stream|wildcard|alias|reserved'}
    $plan=Invoke-WelaEventMeasurement -Channel Security
    Assert ($plan.Status -eq 'Planned' -and $plan.Artifacts.Count -eq 0 -and $plan.ObservedDeliveriesPerSecond -eq $null) 'Plan reads state but creates no evidence or measurement'
    $event=Read-WelaMeasurementEvent -Xml (Event) -Channel Security -Computer @('HOST','HOST.lab.test')
    Assert ($event.RecordId -ceq '10' -and $event.EventId -eq 4688 -and $event.Computer -ceq 'HOST.lab.test') 'Original numeric and qualified computer identities retained'
    $user=Read-WelaMeasurementEvent -Xml (Event -Payload '<UserData><Audit xmlns="urn:provider"><Value>kept</Value></Audit></UserData>') -Channel Security -Computer @('HOST','HOST.lab.test')
    $otherNamespace=Read-WelaMeasurementEvent -Xml (Event -Payload '<UserData><Audit xmlns="urn:other"><Value>kept</Value></Audit></UserData>') -Channel Security -Computer @('HOST','HOST.lab.test')
    $otherValue=Read-WelaMeasurementEvent -Xml (Event -Payload '<UserData><Audit xmlns="urn:provider"><Value>changed</Value></Audit></UserData>') -Channel Security -Computer @('HOST','HOST.lab.test')
    Assert ($user.Key -cne $otherNamespace.Key -and $user.Key -cne $otherValue.Key) 'Provider-specific UserData namespace and fields participate in semantic equality'
    $mixedPayload='<UserData><Payload xmlns="urn:provider" First="1" Second="2">before<Child>value</Child>after</Payload></UserData>'
    $movedPayload='<UserData><Payload xmlns="urn:provider" First="1" Second="2">beforeafter<Child>value</Child></Payload></UserData>'
    $equivalentPayload='<UserData><p:Payload xmlns:p="urn:provider" Second="2" First="1">be<![CDATA[fore]]><p:Child>value</p:Child>after</p:Payload></UserData>'
    $mixed=Read-WelaMeasurementEvent -Xml (Event -Payload $mixedPayload) -Channel Security -Computer @('HOST','HOST.lab.test')
    $moved=Read-WelaMeasurementEvent -Xml (Event -Payload $movedPayload) -Channel Security -Computer @('HOST','HOST.lab.test')
    $equivalent=Read-WelaMeasurementEvent -Xml (Event -Payload $equivalentPayload) -Channel Security -Computer @('HOST','HOST.lab.test')
    Assert ($mixed.Key -cne $moved.Key) 'Moving mixed-content text across an element changes the payload identity'
    Assert ($mixed.Key -ceq $equivalent.Key) 'Equivalent prefixes, attribute order and adjacent text/CDATA preserve payload identity'
    $spaced=Read-WelaMeasurementEvent -Xml (Event -Payload $mixedPayload.Replace('</Child>after','</Child> after')) -Channel Security -Computer @('HOST','HOST.lab.test')
    Assert ($mixed.Key -cne $spaced.Key) 'Mixed-content whitespace remains payload data'
    $indented=Read-WelaMeasurementEvent -Xml (Event -Payload "<UserData>`n  <Audit xmlns=`"urn:provider`">`n    <Value>kept</Value>`n  </Audit>`n</UserData>") -Channel Security -Computer @('HOST','HOST.lab.test')
    Assert ($user.Key -ceq $indented.Key) 'Element-only indentation does not change semantic identity'
    $preserved=Read-WelaMeasurementEvent -Xml (Event -Payload '<UserData><Payload xmlns="urn:provider" xml:space="preserve"> <Child>value</Child> </Payload></UserData>') -Channel Security -Computer @('HOST','HOST.lab.test')
    $preservedChanged=Read-WelaMeasurementEvent -Xml (Event -Payload '<UserData><Payload xmlns="urn:provider" xml:space="preserve">  <Child>value</Child> </Payload></UserData>') -Channel Security -Computer @('HOST','HOST.lab.test')
    Assert ($preserved.Key -cne $preservedChanged.Key) 'Explicit xml:space preservation keeps significant whitespace'
    $nestedPayload='<UserData><Payload xmlns="urn:provider">'+('<Child>'*30)+'kept'+('</Child>'*30)+'</Payload></UserData>'
    $nested=Read-WelaMeasurementEvent -Xml (Event -Payload $nestedPayload) -Channel Security -Computer @('HOST','HOST.lab.test')
    $nestedChanged=Read-WelaMeasurementEvent -Xml (Event -Payload $nestedPayload.Replace('kept','changed')) -Channel Security -Computer @('HOST','HOST.lab.test')
    Assert ($nested.Key.Length -lt 200 -and $nested.Key -cne $nestedChanged.Key) 'Deep valid payload comparison remains bounded and retains the deepest value'
    $tooDeep='<UserData><Payload xmlns="urn:provider">'+('<Child>'*64)+'value'+('</Child>'*64)+'</Payload></UserData>'
    Reject {Read-WelaMeasurementEvent -Xml (Event -Payload $tooDeep) -Channel Security -Computer @('HOST','HOST.lab.test')} '64-element nesting cap'
    $rendered=Read-WelaMeasurementEvent -Xml ((Event).Replace('</Event>','<RenderingInfo Culture="en-US"><Message>display text</Message></RenderingInfo></Event>')) -Channel Security -Computer @('HOST','HOST.lab.test')
    Assert ($rendered.Key -ceq $event.Key) 'Localized RenderingInfo does not change original event semantics'
    foreach($bad in @((Event -Channel System),(Event -Computer OTHER),(Event -Computer 'HOST.other-domain.test'),(Event -Id 0),((Event).Replace('<Version>2</Version>','')),((Event).Replace('<EventData>','<EventData/><EventData>')),('<!DOCTYPE Event [<!ENTITY x SYSTEM "file:///etc/passwd">]>'+(Event)))) {Reject {Read-WelaMeasurementEvent -Xml $bad -Channel Security -Computer @('HOST','HOST.lab.test')} 'identity|match|payload|section|DTD|system|duplicate'}
    Reject {Assert-WelaMeasurementBookmark '<BookmarkList><Bookmark Channel="Security" RecordId="11"/></BookmarkList>' $event} 'does not identify'
    Assert-WelaMeasurementBookmark (Delivery).BookmarkXml $event;$script:checks++
    $many=@(1..41|ForEach-Object {[pscustomobject]@{RecordId=[string]$_}});$query=Get-WelaMeasurementQuery Security $many
    Assert (([xml]$query).QueryList.Query.Select.Count -eq 3 -and $query -match 'EventRecordID=41') 'Structured exact-record query splits more than twenty expressions'
    Reject {Get-WelaMeasurementQuery Security @($event,$event)} 'duplicate'
    $script:capture=Capture @((Delivery 10),(Delivery 11));$script:reopen=@((Event 11),(Event 10))
    $success=Run success -Export
    Assert ($success.Status -eq 'DeliveryWindowObserved' -and $success.ExitCode -eq 0 -and $success.ObservedDeliveriesPerSecond -eq 2) ('Complete measured window: '+$success.Diagnostic)
    Assert ($success.Evtx.Status -eq 'ExactSampleReopened' -and $success.Evtx.Bytes -eq 8 -and $success.Evtx.Records -eq 2) 'Actual export bytes require semantic reopen with every sampled record'
    Assert ($success.ReadyRuleCredit -eq 0 -and $success.PolicyChanges -eq 0 -and $success.LossAssessment -match '^Unknown') 'Measurement gives no rule credit or upstream losslessness claim'
    Assert ($success.Events[0].PSObject.Properties.Name -notcontains 'Key' -and $success.Events[0].XmlArtifact -eq 'event-0001.xml') 'Manifest refers to exact original evidence artifacts'
    foreach($artifact in $success.Artifacts) {Assert ((Get-FileHash -LiteralPath (Join-Path $success.OutputPath $artifact.Name)).Hash.ToLowerInvariant() -ceq $artifact.Sha256) 'Protected artifact hash matches written evidence'}
    $script:capture=Capture @((Delivery));$script:capture.Events[0].Xml=Event -Payload $mixedPayload
    $script:reopen=@((Event -Payload $movedPayload));$changedMixed=Run 'changed-mixed-content' -Export
    Assert ($changedMixed.ExitCode -eq 1 -and $changedMixed.Evtx.Status -eq 'Unverified' -and $null -eq $changedMixed.Evtx.Bytes -and $changedMixed.Diagnostic -match 'identity or payload') 'EVTX reopen rejects moved mixed-content text before exposing verified bytes'
    $script:reopen=@((Event -Payload $equivalentPayload));$equivalentMixed=Run 'equivalent-mixed-content' -Export
    Assert ($equivalentMixed.ExitCode -eq 0 -and $equivalentMixed.Evtx.Status -eq 'ExactSampleReopened') 'EVTX reopen accepts equivalent mixed content without rewriting original XML'
    $script:capture=Capture
    $zero=Run zero -Export
    Assert ($zero.Status -eq 'NoDeliveriesObserved' -and $zero.Evtx.Status -eq 'NotCreatedNoEvents' -and $null -eq $zero.ObservedDeliveriesPerSecond -and -not(Test-Path (Join-Path $zero.OutputPath 'sample.evtx'))) 'Empty window neither invents an EVTX archive nor asserts zero producer rate'
    foreach($status in @('EventCapExceeded','XmlCapExceeded','NativeError')) {
        $script:capture=Capture @((Delivery));$script:capture.Status=$status;$script:capture.Diagnostic='explicit native diagnostic';$script:capture.NativeError=if($status -eq 'NativeError'){15011}else{0}
        $r=Run $status -Export
        Assert ($r.Status -eq 'Unverified' -and $r.ExitCode -eq 1 -and $null -eq $r.ObservedDeliveriesPerSecond -and $r.Diagnostic -match $status -and (Test-Path (Join-Path $r.OutputPath 'event-0001.xml'))) "$status retains partial evidence and suppresses a valid rate"
    }
    foreach($drift in @('reader','mode','created','clear','denied')) {$script:drift=$drift;$script:capture=Capture @((Delivery));$r=Run $drift -Export;Assert ($r.ExitCode -eq 1 -and $null -eq $r.ObservedDeliveriesPerSecond) "$drift invalidates measurement"};$script:drift=''
    foreach($ids in @(@(10,10),@(11,10),@(10,12))) {$script:capture=Capture @($ids|ForEach-Object {Delivery $_});$r=Run ('ids'+($ids -join '-'));Assert ($r.ExitCode -eq 1 -and $r.Diagnostic -match 'discontinuous') 'Duplicate/reordered/gapped delivery IDs are not credited'}
    $script:capture=Capture @((Delivery));$script:capture.Events[0].ElapsedSeconds=1;$r=Run timestamp;Assert ($r.ExitCode -eq 1 -and $r.Diagnostic -match 'outside') 'Out-of-window callback refused'
    $script:capture=Capture @((Delivery))
    foreach($variant in @('empty','extra','changed','wrong-id','wrong-channel')) {
        $script:reopen=switch($variant){'empty'{@()};'extra'{@((Event),(Event 11))};'changed'{@((Event -Payload '<EventData><Data Name="Value">changed</Data></EventData>'))};'wrong-id'{@((Event 11))};'wrong-channel'{@((Event -Channel System))}}
        $r=Run ('export-'+$variant) -Export
        Assert ($r.ExitCode -eq 1 -and $r.Evtx.Status -eq 'Unverified' -and $null -eq $r.Evtx.Bytes -and $null -eq $r.ObservedDeliveriesPerSecond) "EVTX $variant readback cannot produce verified bytes or a valid rate"
    }
    $script:capture=Capture @((Delivery));$script:reopen=@((Event));$script:tamperPath=Join-Path (Join-Path $temp 'post-reopen-tamper') 'sample.evtx'
    $r=Run 'post-reopen-tamper' -Export;$script:tamperPath=$null
    Assert ($r.ExitCode -eq 1 -and $r.Evtx.Status -eq 'Unverified' -and $null -eq $r.Evtx.Bytes -and $r.Diagnostic -match 'Saved event evidence changed') 'Post-reopen sample mutation revokes verified bytes at final manifest freshness check'
    $failure=Get-Content -LiteralPath (Join-Path $r.OutputPath 'manifest.json') -Raw | ConvertFrom-Json
    Assert ($failure.Status -eq 'Unverified' -and $failure.Diagnostic -match 'Final evidence check failed') 'Final artifact mismatch retains a durable unverified manifest'
    # Exercise public dispatch boundaries in a child; expected errors must not terminate PS5.1 before exit capture.
    $engine=(Get-Process -Id $PID).Path
    foreach($args in @(@('configure','-MeasurementAction','Plan'),@('event-measurement','-MeasurementChannel','Security','-Auto'),@('event-measurement','-MeasurementChannel','ForwardedEvents'))) {
        $saved=$ErrorActionPreference;$ErrorActionPreference='Continue'
        try {$output=& $engine -NoProfile -File (Join-Path $repo 'WELA.ps1') @args 2>&1;$code=$LASTEXITCODE} finally {$ErrorActionPreference=$saved}
        Assert ($code -ne 0 -and ($output|Out-String) -match 'Measurement options|dedicated options|exact reviewed') 'Public guard rejects unrelated options or unsupported source before native access'
    }
    Write-Host "$script:checks event measurement assertions passed. Mocks do not establish native event or EVTX success."
} finally {Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}
$global:LASTEXITCODE=0
