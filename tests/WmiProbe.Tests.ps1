$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/AuditProfiles.psm1') -Force
. (Join-Path $repo 'scripts/WefArrival.ps1')
. (Join-Path $repo 'scripts/WmiNamespaceAuditing.ps1')
. (Join-Path $repo 'scripts/WmiProbe.ps1')
Add-Type -Path (Join-Path $repo 'scripts/WmiProbeNative.cs') -ErrorAction Stop
$script:count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Reject($Code,$Pattern){$message='';try{&$Code|Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern, got $message"}
function Clone($Value){ConvertFrom-WelaArrivalJson ($Value|ConvertTo-Json -Depth 24 -Compress)}
# Exercise the actual native token-equivalence gate with synthetic field values.
$equivalent=[Wela.WmiProbe.Native].GetMethod('Equivalent',[Reflection.BindingFlags]'NonPublic,Static')
function NativeToken {
    $t=[Wela.WmiProbe.Token]::new();$t.Sid='S-1-5-21-1-2-3-1001';$t.AuthenticationId='0x123'
    $g=[Wela.WmiProbe.Group]::new();$g.Sid='S-1-1-0';$g.Attributes=7;$t.Groups=@($g)
    $p=[Wela.WmiProbe.Privilege]::new();$p.Luid='0x8';$p.Attributes=0;$t.Privileges=@($p);$t
}
$a=NativeToken;$b=NativeToken;$a.TokenSource='Process';$b.TokenSource='EquivalentSelfThread'
Assert ($equivalent.Invoke($null,@($a,$b))) 'Equivalent runtime self token is accepted without replacement.'
foreach($change in @('Sid','AuthenticationId','GroupSid','GroupAttributes','PrivilegeLuid','PrivilegeAttributes','GroupCount','PrivilegeCount')){
    $b=NativeToken
    switch($change){
        Sid {$b.Sid='S-1-5-18'}
        AuthenticationId {$b.AuthenticationId='0x124'}
        GroupSid {$b.Groups[0].Sid='S-1-5-11'}
        GroupAttributes {$b.Groups[0].Attributes=16}
        PrivilegeLuid {$b.Privileges[0].Luid='0x9'}
        PrivilegeAttributes {$b.Privileges[0].Attributes=2}
        GroupCount {$b.Groups=@()}
        PrivilegeCount {$b.Privileges=@()}
    }
    Assert (-not $equivalent.Invoke($null,@($a,$b))) ('Different effective token is refused: '+$change)
}
$token=[pscustomobject]@{Sid='S-1-5-21-1-2-3-1001';Name='LAB\Reader';AuthenticationId='0x123';AuthenticationType='NTLM';ImpersonationLevel='None';Groups=@([pscustomobject]@{Sid='S-1-1-0';Attributes=7});Privileges=@([pscustomobject]@{Luid='0x8';Attributes=0})}
$descriptor=[pscustomobject]@{ControlFlags=32788;Owner=$null;Group=$null;DACL=@();SACL=@([pscustomobject]@{AceType=2;AceFlags=64;AccessMask=1;Trustee=[pscustomobject]@{SIDString='S-1-1-0'}})}
$state=[pscustomobject][ordered]@{Namespace='root\default';Computer='LAB';Host=[pscustomobject]@{Status='Observed';Build=26100;ProductType=3;DomainJoined=$false};Token=$token;Descriptor=[pscustomobject]@{Namespace='root\default';DescriptorJson=($descriptor|ConvertTo-Json -Depth 10 -Compress);DescriptorMof='fixture descriptor'};AuditMask=1;Precedence=[pscustomobject]@{ValueExists=$true;Type='DWord';Value=1};Channel=[pscustomobject]@{Name='Security';Enabled=$true;SecurityDescriptor='O:SYG:SYD:(A;;0x1;;;SY)'};Engine='/fixture';EngineHash=('a'*64);Sources='fixture-sources'}
$operation=[pscustomobject]@{Namespace='root\default';StartedUtc='2025-01-02T03:04:05.1234500Z';CompletedUtc='2025-01-02T03:04:06.1234500Z';ExpectedAccessMask=1;SecurityRecordIdBefore=100;BeforeToken=$token;AfterToken=$token}
$xml='<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/><EventID>4662</EventID><Version>0</Version><Keywords>0x8020000000000000</Keywords><EventRecordID>101</EventRecordID><Channel>Security</Channel><Computer>LAB</Computer><TimeCreated SystemTime="2025-01-02T03:04:05.5000000Z"/></System><EventData><Data Name="SubjectUserSid">S-1-5-21-1-2-3-1001</Data><Data Name="SubjectLogonId">0x123</Data><Data Name="ObjectServer">WMI</Data><Data Name="ObjectName">root\default</Data><Data Name="AccessMask">0x1</Data></EventData></Event>'
Assert (Test-WelaWmiProbeEvent $xml $operation $state) 'Exact synthetic WMI namespace event matches.'
$mutations=@(
 @('4662','4663'),@('>0</Version>','>1</Version>'),@('>WMI<','>DS<'),@('root\default','root\cimv2'),@('0x1</Data>','0x2</Data>'),@('0x123','0x124'),@('S-1-5-21-1-2-3-1001','S-1-5-21-1-2-3-1002'),@('>LAB<','>OTHER<'),@('>Security<','>Application<'),@('0x8020000000000000','0x8010000000000000'),@('>101<','>100<'),@('03:04:05.5000000Z','03:04:05.1000000Z'),@('03:04:05.5000000Z','03:04:06.5000000Z'),@('54849625-5478-4994-a5ba-3e3b0328c30d','54849625-5478-4994-a5ba-3e3b0328c30e'),@('Name="AccessMask"','Name="SubjectLogonId"'))
foreach($pair in $mutations){$changed=$xml.Replace($pair[0],$pair[1]);Assert ($changed -cne $xml) 'Mutation changed the fixture.';Assert (-not(Test-WelaWmiProbeEvent $changed $operation $state)) ('Reject mismatched '+$pair[0])}
Assert (-not(Test-WelaWmiProbeEvent ('<!DOCTYPE Event [<!ENTITY x "WMI">]>'+$xml.Replace('>WMI<','>&x;<')) $operation $state)) 'DTD input is refused.'
Assert (-not(Test-WelaWmiProbeEvent $xml.Replace('</EventData>','<Data Name="ObjectName">root\default</Data></EventData>') $operation $state)) 'Duplicate event data are refused.'
Assert (-not(Test-WelaWmiProbeEvent $xml.Replace('</System>','<EventID>4662</EventID></System>') $operation $state)) 'Duplicate System fields are refused.'
Assert (-not(Test-WelaWmiProbeEvent ('x'*131073) $operation $state)) 'Oversized raw evidence is refused.'
foreach($name in @('root\default','root\WelaProbe_a123','root\cimv2\security')){Assert-WelaWmiProbeNamespace $name;Assert $true 'Exact local namespace accepted.'}
foreach($name in @('root','ROOT\default','\\remote\root\default','root\default:__SystemSecurity=@','root\*','root\..\default','root/default','root\default;Write-Host x')){Reject {Assert-WelaWmiProbeNamespace $name} 'exact local'}
$null=Get-WelaWmiProbeStateKey $state
foreach($mask in @(0,2,4)){$bad=Clone $state;$bad.AuditMask=$mask;Reject {Get-WelaWmiProbeStateKey $bad} 'success auditing'}
$bad=Clone $state;$bad.Precedence.Type='String';Reject {Get-WelaWmiProbeStateKey $bad} 'typed audit'
$bad=Clone $state;$bad.Channel.Enabled=$false;Reject {Get-WelaWmiProbeStateKey $bad} 'Security channel'
$bad=Clone $state;$bad.Token.Groups[0].Attributes=16;Reject {Get-WelaWmiProbeStateKey $bad} 'No observed success'
foreach($field in @('AceType','AceFlags','AccessMask')){$d=Clone $descriptor;$d.SACL[0].$field=0;$bad=Clone $state;$bad.Descriptor.DescriptorJson=$d|ConvertTo-Json -Depth 10 -Compress;Reject {Get-WelaWmiProbeStateKey $bad} 'No observed success'}
$bad=Clone $state;$bad.Host.Build=99999;Reject {Get-WelaWmiProbeStateKey $bad} 'outside'
Reject {Invoke-WelaWmiProbe -Namespace 'root\default' -Action Run} 'new WmiProbeOutputPath'
Reject {Invoke-WelaWmiProbe -Namespace 'root\default' -OutputPath ignored} 'Plan creates no files'
# Public production report path; only native boundaries are mocked here.
$script:mode='Success';$script:reads=0;$script:workerCalls=0
function Get-WelaWmiProbeState {param($Namespace);$script:reads++;$copy=Clone $state;if($script:mode -eq 'Drift' -and $script:reads -gt 1){$copy.Sources='changed'};if($script:mode -eq 'Blocked'){$copy.AuditMask=0};$copy}
function Start-WelaWmiProbeRead {param($State);$script:workerCalls++;$operation}
function Read-WelaWmiProbeEvents {param($Operation);if($script:mode -eq 'ReadError'){throw 'native read denied'};[pscustomobject]@{Xml=@($xml);Capped=($script:mode -eq 'Cap');Query='fixture bounded query'}}
function Get-WelaWmiProbeWatermark {if($script:mode -eq 'Clear'){99}else{101}}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-wmi-fixtures-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $temp
try{
    $plan=Invoke-WelaWmiProbe -Namespace 'root\default'
    Assert ($plan.Status -eq 'PrerequisitesObserved' -and $script:workerCalls -eq 0) 'Default Plan never invokes the fixed worker.'
    foreach($mode in @('Success','Blocked','Cap','ReadError','Drift','Clear')){
        $script:mode=$mode;$script:reads=0;$script:workerCalls=0;$dir=Join-Path $temp $mode
        $result=Invoke-WelaWmiProbe -Action Run -Namespace 'root\default' -OutputPath $dir -TimeoutSeconds 1
        $manifest=ConvertFrom-WelaArrivalJson ([IO.File]::ReadAllText((Join-Path $dir 'manifest.json')))
        Assert ($manifest.ReadyRuleCredit -eq 0 -and $manifest.PolicyChanges -eq 0 -and $manifest.NamespaceChanges -eq 0) 'Every report retains the no-change/no-readiness boundary.'
        Assert ($null -ne $manifest.After) 'After observation survives success/failure.'
        foreach($artifact in $manifest.Artifacts){Assert ($artifact.Sha256 -ceq (Get-FileHash -LiteralPath (Join-Path $dir $artifact.Name)).Hash.ToLowerInvariant()) 'Manifest artifact hashes match exact written bytes.'}
        if($mode -eq 'Success'){Assert ($result.Status -eq 'LocalNamespaceAccessObserved' -and $result.Matches -eq 1 -and $result.ExitCode -eq 0) 'Public report verifies the bounded event.';Assert ([IO.File]::ReadAllText((Join-Path $dir 'event-1.xml')) -ceq $xml) 'Raw event XML is preserved.'}
        else{Assert ($result.Status -eq 'Unverified' -and $result.ExitCode -eq 1 -and $result.Diagnostic) "Failure $mode never becomes observed."}
        if($mode -eq 'Blocked'){Assert ($script:workerCalls -eq 0) 'Missing prerequisites block worker invocation.'}
    }
    Reject {Invoke-WelaWmiProbe -Action Run -Namespace 'root\default' -OutputPath (Join-Path $temp 'Success')} 'new directory'
}finally{Remove-Item -LiteralPath $temp -Recurse -Force}
Write-Host "PASS: $script:count WMI probe fixtures; native boundaries were mocked."
$global:LASTEXITCODE=0
