$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/WefSubscriptions.psm1') -Force
. (Join-Path $repo 'scripts/WecRuntime.ps1')
Add-Type -Path (Join-Path $repo 'scripts/WecRuntimeNative.cs')
$script:count=0
function Assert($Value,$Message) {if (-not $Value) {throw $Message};$script:count++}
function Throws($Action,$Pattern) {$message='';try {& $Action | Out-Null} catch {$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern; received $message"}
function NativeValue([uint32]$Type,$Data,[uint32]$Count=0) {[pscustomobject]@{State='Observed';NativeType=$Type;Data=$Data;Count=$Count;ErrorCode=0;Diagnostic=''}}
# Decode synthetic native-memory buffers, not a mock of the ABI decoder.
$buffer=[Runtime.InteropServices.Marshal]::AllocHGlobal(256)
try {
    $zero=New-Object byte[] 256;[Runtime.InteropServices.Marshal]::Copy($zero,0,$buffer,256)
    [Runtime.InteropServices.Marshal]::WriteInt32($buffer,12,2)
    [Runtime.InteropServices.Marshal]::WriteInt32($buffer,0,-1)
    $decoded=[Wela.WecRuntime.Native]::Decode($buffer,16,1)
    Assert ($decoded.Data -is [uint32] -and $decoded.Data -eq [uint32]::MaxValue) 'UInt32 error codes keep their unsigned width.'
    Throws {[Wela.WecRuntime.Native]::Decode($buffer,16,2)} 'Unexpected EC_VARIANT'
    Throws {[Wela.WecRuntime.Native]::Decode($buffer,15,1)} 'Invalid runtime buffer'
    [Runtime.InteropServices.Marshal]::WriteInt32($buffer,12,3)
    [Runtime.InteropServices.Marshal]::WriteInt64($buffer,0,[DateTime]::UtcNow.ToFileTimeUtc())
    Assert (([Wela.WecRuntime.Native]::Decode($buffer,16,6)).Data -is [uint64]) 'FILETIME retains unsigned64 representation.'
    [Runtime.InteropServices.Marshal]::WriteInt32($buffer,12,4)
    $text=[Text.Encoding]::Unicode.GetBytes("日本語 Fehler`0");$textPointer=[IntPtr]::Add($buffer,64)
    [Runtime.InteropServices.Marshal]::Copy($text,0,$textPointer,$text.Length)
    [Runtime.InteropServices.Marshal]::WriteIntPtr($buffer,0,$textPointer)
    Assert (([Wela.WecRuntime.Native]::Decode($buffer,256,2)).Data -ceq '日本語 Fehler') 'Native strings are Unicode without English parsing.'
    [Runtime.InteropServices.Marshal]::WriteIntPtr($buffer,0,[IntPtr]::Add($buffer,256))
    Throws {[Wela.WecRuntime.Native]::Decode($buffer,256,2)} 'outside'
    [Runtime.InteropServices.Marshal]::WriteInt32($buffer,12,132)
    [Runtime.InteropServices.Marshal]::WriteInt32($buffer,8,1)
    [Runtime.InteropServices.Marshal]::WriteIntPtr($buffer,0,[IntPtr]::Add($buffer,24))
    [Runtime.InteropServices.Marshal]::WriteIntPtr($buffer,24,$textPointer)
    Assert (([Wela.WecRuntime.Native]::Decode($buffer,256,5)).Data[0] -ceq '日本語 Fehler') 'Source string-array pointer layout is decoded.'
    [Runtime.InteropServices.Marshal]::WriteInt32($buffer,8,4097)
    Throws {[Wela.WecRuntime.Native]::Decode($buffer,256,5)} '4096'
    [Runtime.InteropServices.Marshal]::WriteInt32($buffer,8,0)
    [Runtime.InteropServices.Marshal]::WriteInt32($buffer,12,0)
    Assert (([Wela.WecRuntime.Native]::Decode($buffer,16,2)).State -eq 'NotAvailable') 'Null is distinct from a successful nonempty property.'
} finally {[Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)}
foreach ($property in @(0,1)) {
    Throws {ConvertTo-WelaWecRuntimeField (NativeValue 2 '2') $property} 'UInt32'
    $nullValue=[pscustomobject]@{State='NotAvailable';NativeType=0;ErrorCode=0;Diagnostic=''}
    Assert ((ConvertTo-WelaWecRuntimeField $nullValue $property).Status -eq 'Unknown') 'Missing mandatory runtime values cannot make a complete observation.'
}
Assert ((ConvertTo-WelaWecRuntimeField (NativeValue 2 ([uint32]99)) 0).Status -eq 'Unknown') 'Unknown future native enum keeps uncertainty.'
Assert ((ConvertTo-WelaWecRuntimeField (NativeValue 3 ([uint64]0)) 6).Status -eq 'NotAvailable') 'Zero heartbeat is not a1601 observed timestamp.'
Assert ((ConvertTo-WelaWecRuntimeField (NativeValue 3 ([uint64]::MaxValue)) 6).Status -eq 'Unknown') 'Out-of-range FILETIME is not silently rounded.'
$utc=[DateTime]::SpecifyKind([DateTime]'2025-01-02T03:04:05',[DateTimeKind]::Utc)
$time=ConvertTo-WelaWecRuntimeField (NativeValue 3 ([uint64]$utc.ToFileTimeUtc())) 6
Assert ($time.Value -ceq '2025-01-02T03:04:05.0000000Z') 'FILETIME renders UTC without labeling local time Z.'

$script:scenario='';$script:contextReads=0;$script:definitionReads=0;$script:inventoryReads=0;$script:nativeReads=0
$definitionReader=(Get-Command Get-WelaWecRuntimeDefinition).ScriptBlock
function Reset-Fixture {$script:scenario='';$script:contextReads=0;$script:definitionReads=0;$script:inventoryReads=0;$script:nativeReads=0}
function Get-WelaWecRuntimeContext {
    $script:contextReads++
    if ($script:scenario -eq 'context-denied') {throw 'Reader context unavailable'}
    [pscustomobject]@{Computer='FixtureCollector';ReaderSid=$(if ($script:scenario -eq 'context-drift' -and $script:contextReads -gt 1) {'OTHER'} else {'S-1-5-18'});Host=[pscustomobject]@{Build=26100;DomainRole=3}}
}
function Get-WelaWecRuntimeDefinition {
    param($Id)
    $script:definitionReads++
    if ($script:scenario -eq 'definition-denied') {throw 'Definition access denied'}
    [pscustomobject]@{Id=$Id;Type='SourceInitiated';Enabled=$false;Key=$(if ($script:scenario -eq 'definition-drift' -and $script:definitionReads -gt 1) {'changed'} else {'same'});RawXml='<Subscription/>'}
}
function Read-WelaWecRuntimeValue {
    param($Id,$Source,$Property)
    $script:nativeReads++
    if (($script:scenario -eq 'field-denied' -and $Property -eq 1) -or ($script:scenario -eq 'one-source-denied' -and $Source -eq 'source2' -and $Property -eq 0)) {return [pscustomobject]@{State='Unknown';NativeType=$null;Count=0;ErrorCode=5;Data=$null;Diagnostic='Localized access denied'}}
    switch ($Property) {
        0 {NativeValue 2 ([uint32]$(if ($script:scenario -eq 'active') {2} elseif ($script:scenario -eq 'trying') {4} else {1}))}
        1 {NativeValue 2 ([uint32]$(if ($script:scenario -eq 'trying') {1722} else {0}))}
        2 {NativeValue 4 'Lokalisierte Nachricht <script>'}
        5 {
            $script:inventoryReads++
            $sources=@('source1','source2')
            if ($script:scenario -eq 'empty') {$sources=@()}
            if ($script:scenario -eq 'duplicate') {$sources=@('source1','SOURCE1')}
            if ($script:scenario -eq 'source-drift' -and $script:inventoryReads -gt 1) {$sources=@('source1')}
            NativeValue 132 $sources $sources.Count
        }
        default {NativeValue 3 ([uint64]0)}
    }
}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-wec-runtime-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $temp
try {
    foreach ($case in @('','active','trying','empty')) {
        Reset-Fixture;$script:scenario=$case;$report=Get-WelaWecRuntime 'Fixture'
        Assert ($report.Status -eq 'Observed') "$case yields a complete observation without claiming health."
        Assert ($report.ReadyRuleCredit -eq 0 -and $report.EventArrival -eq 'Not tested' -and $report.Backlog -eq 'Unknown') 'Native status grants no arrival/backlog/Ready proof.'
        Assert ($report.SourceInventory.Meaning -match '30 days' -and $report.SourceInventory.Meaning -match 'not a current connection') 'Source inventory retains documented historical meaning.'
        if ($case -eq 'trying') {Assert ($report.Subscription.Activity -eq 'Trying' -and $report.Subscription.Fields.LastError.Value -eq 1722) 'Trying and numeric native failure remain visible despite successful reads.'}
        if ($case -eq 'empty') {Assert ($report.SourceInventory.ReportedCount -eq 0 -and $report.Sources.Count -eq 0) 'Empty source array is an observed empty inventory, never active sources.'}
    }
    foreach ($case in @('field-denied','one-source-denied','definition-drift','context-drift','source-drift','duplicate')) {
        Reset-Fixture;$script:scenario=$case;$report=Get-WelaWecRuntime 'Fixture'
        Assert ($report.Status -eq 'Partial') "$case cannot return complete observation."
        Assert ($null -ne $report.CollectorAfter) 'Partial observation retains actual final collector context.'
        if ($case -eq 'field-denied') {Assert ($report.Subscription.Fields.LastError.ErrorCode -eq 5 -and $report.Subscription.Fields.LastError.Status -eq 'Unknown') 'Native read error code is separate from subscription LastError value.'}
    }
    foreach ($case in @('definition-denied','context-denied')) {Reset-Fixture;$script:scenario=$case;$report=Get-WelaWecRuntime 'Fixture';Assert ($report.Status -eq 'Unknown' -and $script:nativeReads -eq 0) 'Unverified context/definition stops runtime queries.'}
    Reset-Fixture;$report=Get-WelaWecRuntime 'Fixture' -MaximumSources 1
    Assert ($report.Status -eq 'Partial' -and $report.Capped -and $report.Sources.Count -eq 1 -and $report.SourceInventory.ReportedCount -eq 2) 'Source cap keeps actual denominator and explicit incompleteness.'
    Assert ($script:nativeReads -eq 14) 'Source cap bounds actual per-source native calls.'
    Reset-Fixture
    Throws {Invoke-WelaWecRuntime @('Fixture','fixture')} 'duplicate'
    Throws {Invoke-WelaWecRuntime @()} '1..32'
    Throws {Invoke-WelaWecRuntime @('../other')} 'Invalid'
    Push-Location $temp
    try {$report=Invoke-WelaWecRuntime @('Fixture') -ResultsPath './runtime.json';Assert (Test-Path ./runtime.json) 'Relative output uses PowerShell location.';Throws {Invoke-WelaWecRuntime @('Fixture') -ResultsPath './runtime.json'} 'new ordinary'} finally {Pop-Location}
    $json=Get-Content -LiteralPath (Join-Path $temp 'runtime.json') -Raw | ConvertFrom-Json
    Assert ($json.Subscriptions[0].Subscription.Fields.LastErrorMessage.Value -ceq 'Lokalisierte Nachricht <script>') 'JSON preserves localized text and exact nested observations.'
    # Exercise actual definition parser with only native process execution replaced.
    function Invoke-WelaNative {param($FilePath,$Arguments) [pscustomobject]@{ExitCode=0;Diagnostic=$script:xml}}
    $script:xml='<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription"><SubscriptionId>Fixture</SubscriptionId><SubscriptionType>SourceInitiated</SubscriptionType><Enabled>false</Enabled><Query>&lt;QueryList&gt;&lt;Query Id="0" Path="Security"&gt;&lt;Select&gt;*&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Query></Subscription>'
    Assert ((& $definitionReader 'Fixture').Enabled -eq $false) 'Native definition parser retains disabled state.'
    Throws {& $definitionReader 'Other'} 'identity'
    $script:xml=$script:xml.Replace('Path="Security"','Path="Microsoft-Windows-Sysmon/Operational"')
    Throws {& $definitionReader 'Fixture'} 'Sysmon'
    # Both older inventories preserve raw evidence and add typed observations.
    . (Join-Path $repo 'scripts/WefDeployment.ps1')
    . (Join-Path $repo 'scripts/RetentionHealth.ps1')
    function Get-WelaNativeChannel {param($Name) [pscustomobject]@{Name=$Name}}
    function Get-WelaWefControlState {[pscustomobject]@{Exists=$true;Definition=[pscustomobject]@{Enabled=$false}}}
    $script:xml='<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription"><Enabled>false</Enabled><Query>&lt;QueryList&gt;&lt;Query Id="0" Path="Security"&gt;&lt;Select&gt;*&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Query></Subscription>'
    Reset-Fixture
    $input=[pscustomobject]@{Subscriptions=@([pscustomobject]@{Id='Fixture';SourceSids=@();Definition=[pscustomobject]@{Enabled=$false};Query=[pscustomobject]@{Channels=@('Security');Filters=@()}})}
    $wef=Get-WelaWefInventory $input Collector
    Assert ($wef.Runtime.Raw -ceq $script:xml -and $wef.TypedRuntime.Status -eq 'Observed') 'WEF inventory retains raw runtime evidence alongside typed result.'
    $source=Get-WelaWefInventory $input Source
    Assert ($null -eq $source.TypedRuntime -and $null -eq $source.Runtime) 'Source inventory does not claim collector runtime observations.'
    $retention=Get-WelaRetentionSubscriptions @('Fixture')
    Assert ($retention.Runtime.Raw -ceq $script:xml -and $retention.TypedRuntime.Status -eq 'Observed' -and $retention.DeliveryHealth -eq 'Unknown') 'Retention adds typed observations without promoting delivery health.'
    $exe=(Get-Process -Id $PID).Path
    foreach ($arguments in @(@('configure','-WecRuntimeId','Fixture'),@('wec-runtime','-Auto'),@('wec-runtime','-Profile','wela-2.2.0'))) {
        $old=$ErrorActionPreference;$ErrorActionPreference='Continue'
        try {$output=& $exe -NoProfile -File (Join-Path $repo 'WELA.ps1') @arguments 2>&1;$code=$LASTEXITCODE} finally {$ErrorActionPreference=$old}
        Assert ($code -ne 0 -and ($output -join ' ') -match 'No command was run') 'Public early guard prevents unrelated options from dispatching.'
    }
} finally {Remove-Item -LiteralPath $temp -Recurse -Force}
$global:LASTEXITCODE=0
Write-Host "WEC runtime: $script:count assertions passed. Synthetic native buffers and observations; no subscriptions or services changed."
