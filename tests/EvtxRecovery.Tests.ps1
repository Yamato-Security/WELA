$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/AuditProfiles.psm1') -Force
. (Join-Path $repo 'scripts/ControlApplicability.ps1')
. (Join-Path $repo 'scripts/NativeValidation.ps1')
. (Join-Path $repo 'scripts/EvtxRecovery.ps1')
. (Join-Path $PSScriptRoot 'fixtures/EvtxRecovery.Fixture.ps1')
$script:checks=0
function Assert($Value,[string]$Message){if(-not $Value){throw "FAIL: $Message"};$script:checks++}
function Reject([scriptblock]$Code,[string]$Pattern){$message='';try{& $Code|Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern; got $message"}
function Clone($Value){ConvertFrom-WelaEvtxJson ($Value|ConvertTo-Json -Depth 24)}
function Save($Path,$Value){[IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 24),[Text.UTF8Encoding]::new($false))}
function Update-Source($Directory,$Name,$Value) {
    Save (Join-Path $Directory $Name) $Value
    $m=ConvertFrom-WelaEvtxJson (Get-Content (Join-Path $Directory 'manifest.json') -Raw)
    ($m.Artifacts|Where-Object path -eq $Name).sha256=(Get-FileHash (Join-Path $Directory $Name)).Hash.ToLowerInvariant()
    switch($Name){'before-state.json'{$m.BeforeState=$Value};'after-state.json'{$m.AfterState=$Value};'process.json'{$m.Process=$Value}}
    Save (Join-Path $Directory 'manifest.json') $m
}
function Start-WelaProbeProcess {throw 'Forbidden process launch'}
function Invoke-WelaNative {throw 'Forbidden native mutation'}
function Set-ItemProperty {throw 'Forbidden registry mutation'}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-evtx-tests-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $temp
try {
    $fixture=New-WelaEvtxFixture (Join-Path $temp 'source')
    $source=Import-WelaEvtxProbe $fixture.Directory
    Assert ($source.Event.Computer -eq 'source01.lab.test' -and $source.Files.Count -eq 5) 'Completed native-shaped source bundle validates with all hashes'
    foreach($case in @('hash','extra','duplicate-json','bad-status','embedded','typed','missing-mask','source-drift','time','process-command','unknown-field','bad-kind','duplicate-artifact')) {
        $dir=Join-Path $temp $case;Copy-Item $fixture.Directory $dir -Recurse
        $m=Clone $fixture.Manifest
        switch($case){
            'hash'{Add-Content (Join-Path $dir 'event.xml') 'tampered'}
            'extra'{Set-Content (Join-Path $dir 'extra.txt') 'extra'}
            'duplicate-json'{$t=Get-Content (Join-Path $dir 'manifest.json') -Raw;$t=$t -replace '"SchemaVersion": 1,','"SchemaVersion": 1, "SchemaVersion": 1,';[IO.File]::WriteAllText((Join-Path $dir 'manifest.json'),$t)}
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
        Reject {Import-WelaEvtxProbe $dir} 'hash|five|Duplicate|successful|differs|DWORD|59-subcategory|drifted|timestamps|fixed|Unexpected'
    }
    foreach($text in @('{"x":1,"X":2}','{x:1}','{"x":1,}',"{'x':1}",'{"x":NaN}')) {Reject {ConvertFrom-WelaEvtxJson $text} 'JSON|Duplicate|strict'}
    $rendered=$fixture.Xml.Replace('</Event>','<RenderingInfo Culture="en-US"><Message>Localized &lt;script&gt; text</Message></RenderingInfo></Event>')
    Assert ((Read-WelaEvtxEvent $rendered).Key -ceq $source.Event.Key) 'RenderingInfo does not change original event identity'
    Assert ((Read-WelaEvtxEvent ($fixture.Xml.Replace('>LAB</Data>','>   </Data>'))).Key -cne (Read-WelaEvtxEvent ($fixture.Xml.Replace('>LAB</Data>','></Data>'))).Key) 'Whitespace-only original payload values remain distinct from empty values'
    foreach($change in @(@('source01.lab.test','wrong.lab.test'),@('0x7b','0x7c'),@('S-1-16-16384','S-1-16-8192'),@('%%1936','%%1937'),@('<EventRecordID>100','<EventRecordID>101'),@('<Version>2','<Version>1'),@('WELA_PROBE_0123456789abcdef0123456789abcdef','WELA_PROBE_1123456789abcdef0123456789abcdef'))) {
        Assert ((Read-WelaEvtxEvent ($fixture.Xml.Replace($change[0],$change[1]))).Key -cne $source.Event.Key) "Original event mutation stays unmatched: $($change[0])"
    }
    foreach($xml in @($fixture.Xml.Replace('</Event>','<UserData/></Event>'),$fixture.Xml.Replace('</Event>','<System/></Event>'),('<!DOCTYPE Event [<!ENTITY a SYSTEM "file:///etc/passwd">]>'+$fixture.Xml))) {Reject {Read-WelaEvtxEvent $xml} 'System|DTD'}
    $script:scenario='match';$script:reads=0;$script:exports=0
    function Get-WelaEvtxReader {
        $script:reads++
        [pscustomobject]@{Computer='reader01';HostKey='WindowsServer2025';Reader=[pscustomobject]@{Sid=$(if ($scenario -eq 'reader-drift' -and $reads -gt 1) {'S-1-5-20'}else{'S-1-5-18'})}}
    }
    function Get-WelaProbeState {ConvertTo-WelaEvtxState (Clone $fixture.Manifest.BeforeState)}
    function Read-WelaEvtxNative {
        param($Path,[switch]$Live,$Query)
        if ($scenario -eq 'denied') {throw 'Native reader denied'}
        if ($scenario -eq 'corrupt') {throw 'Invalid native EVTX format'}
        if ($scenario -eq 'source-change') {Add-Content -LiteralPath (Join-Path $fixture.Directory 'event.xml') 'tampered'}
        $events=@($fixture.Xml)
        if ($scenario -eq 'empty' -and -not $Live) {$events=@()}
        if ($scenario -eq 'duplicate') {$events=@($fixture.Xml,$fixture.Xml)}
        if ($scenario -eq 'wrong') {$events=@($fixture.Xml.Replace('<EventRecordID>100','<EventRecordID>101'))}
        [pscustomobject]@{Xml=$events;Limit=2}
    }
    function Export-WelaEvtxNative {param($Query,$Path) $script:exports++;Assert ($Query -match 'EventRecordID=100' -and $Query -match 'EventID=4688' -and $Query -match 'Security-Auditing') 'Export selects one source record only';[IO.File]::WriteAllBytes($Path,[byte[]](1,2,3,4))}
    function Invoke-Case([string]$Name,[string]$Action='Verify') {
        $script:reads=0;$script:scenario=$Name
        $args=@{Action=$Action;ProbePath=$fixture.Directory;OutputPath=(Join-Path $temp ([guid]::NewGuid().ToString('N')))}
        if ($Action -eq 'Verify') {$args.ArchivePath=$script:archive}
        Invoke-WelaEvtxRecovery @args
    }
    $script:archive=Join-Path $temp 'fixture.evtx';[IO.File]::WriteAllBytes($archive,[byte[]](1,2,3,4))
    $result=Invoke-Case match
    Assert ($result.Status -eq 'NativeEventRecovered' -and $result.ExitCode -eq 0 -and $result.ReadyRuleCredit -eq 0 -and $result.PolicyChanges -eq 0 -and $result.RecoveredEvents -eq 1) 'Exact recovery records presence and keeps readiness separate'
    Assert ($result.ArchiveSha256 -ceq (Get-FileHash -LiteralPath $archive).Hash.ToLowerInvariant()) 'Receipt hashes actual archive bytes'
    Assert (Test-Path (Join-Path $result.OutputPath 'recovered-event.xml')) 'Recovered raw XML retained'
    foreach ($case in @('empty','duplicate','wrong','denied','corrupt','reader-drift')) {
        $result=Invoke-Case $case
        Assert ($result.Status -eq 'Unverified' -and $result.ExitCode -eq 1 -and $result.Diagnostic) "$case cannot establish recovery"
    }
    $result=Invoke-Case match Export
    Assert ($result.Status -eq 'NativeEventRecovered' -and $exports -eq 1 -and (Test-Path $result.ArchivePath)) 'Export requires live source plus native reopening of output'
    $result=Invoke-Case empty Export
    Assert ($result.Status -eq 'Unverified' -and $result.Diagnostic -match 'exactly one') 'Successful native export with empty archive is not recovery proof'
    $count=$exports;$result=Invoke-Case wrong Export
    Assert ($result.ExitCode -eq 1 -and $exports -eq $count) 'Changed/reused source record refuses export before creation'
    $script:scenario='match'
    Reject {Invoke-WelaEvtxRecovery -Action Export -ProbePath $fixture.Directory -ArchivePath $archive -OutputPath (Join-Path $temp 'bad')} 'Export creates'
    Reject {Invoke-WelaEvtxRecovery -Action Verify -ProbePath $fixture.Directory -OutputPath (Join-Path $temp 'bad')} 'requires ArchivePath'
    Reject {Invoke-WelaEvtxRecovery -ProbePath $fixture.Directory -ArchivePath $archive -OutputPath $fixture.Directory} 'outside|new directory'
    Push-Location $temp
    try {$script:reads=0;$result=Invoke-WelaEvtxRecovery -ProbePath ./source -ArchivePath ./fixture.evtx -OutputPath ./relative;Assert ($result.ExitCode -eq 0 -and (Test-Path ./relative/manifest.json)) 'Relative paths follow PowerShell location'} finally {Pop-Location}
    $result=Invoke-Case source-change
    Assert ($result.ExitCode -eq 1 -and $result.Diagnostic -match 'hash') 'Source changed during read is rejected'
    $engine=(Get-Process -Id $PID).Path
    foreach ($arguments in @(@('configure','-EvtxAction','Export'),@('evtx-recovery','-DryRun'),@('evtx-recovery','-Profile','wela-2.2.0'))) {
        $old=$ErrorActionPreference;$ErrorActionPreference='Continue'
        $out=& $engine -NoProfile -File (Join-Path $repo 'WELA.ps1') @arguments 2>&1;$exit=$LASTEXITCODE
        $ErrorActionPreference=$old
        Assert ($exit -ne 0 -and ($out -join ' ') -match 'require evtx-recovery|only its dedicated') 'CLI rejects ignored/incompatible options before dispatch'
    }
} finally {Remove-Item -LiteralPath $temp -Recurse -Force}
$global:LASTEXITCODE=0
Write-Host "EVTX recovery: $script:checks assertions passed."
