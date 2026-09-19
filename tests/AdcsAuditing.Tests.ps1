$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent;$script:ScriptRoot=$root
. (Join-Path $root 'scripts/Configuration.ps1')
. (Join-Path $root 'scripts/AdcsAuditing.ps1')
Import-Module (Join-Path $root 'modules/AuditProfiles.psm1') -Force
$script:count=0
function Assert($Condition,$Message){if(-not $Condition){throw $Message};$script:count++}
function Throws($Action,$Pattern){$message='';try{&$Action|Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern; got $message"}
function Copy-State($Value){$Value|ConvertTo-Json -Depth 20|ConvertFrom-Json}
function Reg($Value,$Type='DWord'){[pscustomobject]@{KeyExists=$true;ValueExists=$true;Value=$Value;Type=$Type}}
$source=Get-WelaAdcsSource
Assert ($source.AuditGuid -ieq '0cce9221-69ae-11d9-bed3-505054503030' -and $source.AuditMask -eq 3 -and $source.AuditMode -eq 'minimum' -and $source.AuditFilter -eq 127) 'CA requirements bind the canonical shared identity profile and official filter.'
Throws {Get-WelaAdcsSource unknown} 'Unknown AD CS'
$nativeHash='0c e5 0d fc 5a f0 70 1d ee 73 90 dd a7 6b 14 bf 97 9a bc 27'
Assert ((ConvertTo-WelaAdcsThumbprints @($nativeHash)) -ceq '0CE50DFC5AF0701DEE7390DDA76B14BF979ABC27') 'Actual native twenty-octet CACertHash normalizes for certificate lookup.'
Assert ((ConvertTo-WelaAdcsThumbprints @($nativeHash.Replace(' ',''))) -ceq '0CE50DFC5AF0701DEE7390DDA76B14BF979ABC27') 'Certificate-store contiguous form retains the same identity.'
Throws {ConvertTo-WelaAdcsThumbprints @($nativeHash,$nativeHash.Replace(' ','').ToUpperInvariant())} 'duplicated'
foreach($invalid in @($nativeHash.Replace(' ','-'),($nativeHash+' 00'),$nativeHash.Substring(3),$nativeHash.Replace(' ','  '),(' '+$nativeHash),42)){
    Throws {ConvertTo-WelaAdcsThumbprints @($invalid)} 'malformed'
}
Throws {ConvertTo-WelaAdcsThumbprints @()} 'empty'
$base=[pscustomobject]@{Status='Supported';Diagnostic='fixture';CapturedUtc='2026-09-20T00:00:00Z';Host=[pscustomobject]@{Computer='CAHOST';DnsHostName='CAHOST';Build=20348;UBR=1;Edition='ServerDatacenter';ProductType=3;DomainRole=2;DomainJoined=$false;Domain='WORKGROUP'};Active=(Reg 'CA-A' String);Path='HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\CA-A';CaType=(Reg 3);CertificateHashes=(Reg @('A'*40) MultiString);Certificates=@([pscustomobject]@{Thumbprint=('A'*40);Sha256=('b'*64);Subject='CN=CA-A';SerialNumber='01'});Filter=(Reg 0);Service=[pscustomobject]@{Name='CertSvc';Status='Running';StartMode='Auto';ProcessId=100;StartUtc='2026-09-19T00:00:00Z';Dependents=@()};AuditMask=0;Precedence=(Reg 0)}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-ca-fixtures-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $temp
$script:ordinal=0
function Reset {
    $script:state=Copy-State $base;$script:writes=@();$script:restarts=0;$script:reads=0;$script:promptAction=$null;$script:readAction=$null;$script:writeAction=$null;$script:restartFail=$false;$script:auditFail=$false;$script:filterFail=$false;$script:decline=$false
}
function Get-WelaAdcsSnapshot {$script:reads++;if($script:readAction){&$script:readAction};Copy-State $script:state}
function Set-ItemProperty {param($LiteralPath,$Name,$Value,$Type,$ErrorAction)
    if($Name -eq 'AuditFilter' -and $script:filterFail){throw 'Injected CA filter write failure'}
    $script:writes+=@([pscustomobject]@{Path=$LiteralPath;Name=$Name;Value=$Value;Type=$Type})
    if($Name -eq 'AuditFilter') {if($LiteralPath -cne $script:state.Path){throw 'Wrong CA target'};$script:state.Filter=Reg $Value $Type}
    elseif($Name -eq 'SCENoApplyLegacyAuditPolicy'){$script:state.Precedence=Reg $Value $Type}
    else{throw 'Unexpected registry write'}
    if($script:writeAction){&$script:writeAction $Name}
}
function Set-WelaEffectiveAuditPolicy {param($Guid,$Mask,$Mode)
    if($script:auditFail){throw 'Audit policy rejected'}
    if($Guid -ine $source.AuditGuid -or $Mask -ne 3 -or $Mode -ne 'minimum'){throw 'Unexpected audit mutation'}
    $script:writes+=@([pscustomobject]@{Name='AuditMask';Value=$Mask});$script:state.AuditMask=$script:state.AuditMask -bor $Mask
}
function Restart-WelaAdcsService {$script:restarts++;if($script:restartFail){throw 'Injected restart failure'};$script:state.Service.ProcessId=101;$script:state.Service.StartUtc='2026-09-20T01:00:00Z'}
function Read-Host {param($Prompt)if($script:promptAction){&$script:promptAction};if($script:decline){'n'}else{'y'}}
function Context([switch]$DryRun,[switch]$Prompt){$script:ordinal++;New-WelaConfigurationContext -Auto:(-not $Prompt) -DryRun:$DryRun -BackupPath (Join-Path $temp "backup-$script:ordinal")}
function Run($Context,[switch]$Legacy,[switch]$NoRestart){
    if($Legacy){Invoke-WelaLegacyAdcsControl $Context;$null}else{Set-WelaAdcsControls -Context $Context -Source $source -Snapshot (Copy-State $script:state) -ConfigurePrerequisites -AllowRestart:(-not $NoRestart)}
}
try {
    Reset;$ctx=Context -DryRun;$outcome=Run $ctx
    Assert ($script:writes.Count -eq 0 -and $script:restarts -eq 0 -and -not (Test-Path $ctx.BackupPath)) 'Dry run creates no recovery directory or Windows changes.'
    Assert ($ctx.Results.Count -eq 3 -and @($ctx.Results|Where-Object Status -eq 'Skipped').Count -eq 3) 'Dry-run lists both prerequisites and filter without pretending applied.'
    Reset;$ctx=Context;$outcome=Run $ctx -NoRestart
    Assert ($script:writes.Count -eq 0 -and $ctx.Results[0].Diagnostic -match 'AllowRestart') 'Dedicated filter change without restart consent refuses every setting write.'
    Reset;$ctx=Context;$outcome=Run $ctx;$done=Complete-WelaConfiguration $ctx
    Assert ($done.ExitCode -eq 0 -and $script:writes.Count -eq 3 -and $script:restarts -eq 1 -and $script:state.AuditMask -eq 3) 'Source prerequisites precede explicit CA filter write and one restart.'
    Assert (($script:writes.Name -join ',') -eq 'SCENoApplyLegacyAuditPolicy,AuditMask,AuditFilter' -and $script:writes[2].Path -ceq $base.Path) 'Writes use canonical order and pinned CA key rather than implicit active certutil selection.'
    Assert ($outcome.Activation -match '^RestartObservedAfterWrite' -and $outcome.Activation -match 'unverified') 'Restart evidence never establishes event generation.'
    $journal=@(Get-Content -LiteralPath (Join-Path $ctx.BackupPath 'before.jsonl')|ForEach-Object{$_|ConvertFrom-Json})
    Assert ($journal.Count -eq 3 -and $journal[2].Before.Active.Value -ceq 'CA-A' -and $journal[2].Before.Certificates[0].Sha256 -ceq ('b'*64) -and $journal[2].Before.Filter.Value -eq 0 -and $journal[2].Before.Precedence.Value -eq 1 -and $journal[2].Before.AuditMask -eq 3) 'Journal binds exact CA identity/certificate/typed filter and verified prerequisites before mutation.'
    $before=Copy-State $script:state;$priorWriteCount=$script:writes.Count;$ctx=Context;$outcome=Run $ctx;$done=Complete-WelaConfiguration $ctx
    Assert ($done.ExitCode -eq 0 -and $script:writes.Count -eq $priorWriteCount -and $script:restarts -eq 1 -and $outcome.Activation -eq 'Unverified') 'Idempotent 127+Running observes policy matches without another restart or invented activation.'
    foreach($mutation in @({$script:state.Active.Value='CA-B';$script:state.Path=$script:state.Path.Replace('CA-A','CA-B')},{$script:state.CaType.Value=4},{$script:state.Certificates[0].Sha256='c'*64},{$script:state.Filter.Value=64},{$script:state.Service.StartMode='Manual'},{$script:state.Service.ProcessId=222},{$script:state.AuditMask=2},{$script:state.Precedence.Value=1})){
        Reset;$script:promptAction=$mutation;$ctx=Context -Prompt;$outcome=Run $ctx
        Assert ($script:writes.Count -eq 0 -and $script:restarts -eq 0 -and @($ctx.Results|Where-Object Status -eq 'Failed').Count -eq 1) 'Prompt-time CA identity/type/certificate/filter/service/prerequisite drift blocks writes.'
    }
    # Exact legacy regression: CA-A was read and journaled, Active then changes to
    # CA-B during confirmation. No registry write may affect either identity.
    Reset;$script:state.AuditMask=3;$script:state.Precedence=Reg 1;$script:promptAction={$script:state.Active.Value='CA-B';$script:state.Path=$script:state.Path.Replace('CA-A','CA-B')};$ctx=Context -Prompt;Run $ctx -Legacy
    Assert ($ctx.Results[0].Status -eq 'Failed' -and $script:writes.Count -eq 0 -and $script:restarts -eq 0) 'Legacy CA-A to CA-B race fails before any filter write/restart.'
    foreach($scenario in @('stopped','disabled','unknown','dependencies')){
        Reset
        switch($scenario){'stopped'{$script:state.Service.Status='Stopped'}'disabled'{$script:state.Service.StartMode='Disabled'}'unknown'{$script:state.Status='Unknown';$script:state.Diagnostic='Unknown type'}'dependencies'{$script:state.Service.Dependents=@([pscustomobject]@{Name='OtherService';Status='Running'})}}
        $ctx=Context;$outcome=Run $ctx
        Assert ($script:writes.Count -eq 0 -and $script:restarts -eq 0 -and $ctx.Results[0].Status -eq 'Failed') 'Unavailable/unsafe CA states never start a service or change prerequisites.'
    }
    Reset;$script:auditFail=$true;$ctx=Context;$outcome=Run $ctx
    Assert ($script:writes.Count -eq 1 -and $script:restarts -eq 0 -and $script:state.Filter.Value -eq 0) 'Failed Certification Services prerequisite blocks CA filter and restart.'
    Reset;$script:state.AuditMask=3;$script:state.Precedence=Reg 1;$script:filterFail=$true;$ctx=Context;Run $ctx -Legacy;$done=Complete-WelaConfiguration $ctx
    Assert ($done.ExitCode -eq 1 -and $script:state.Filter.Value -eq 0 -and $script:restarts -eq 0) 'Actual legacy engine filter write failure cannot restart the CA or report success.'
    Reset;$ctx=Context -DryRun;Run $ctx -Legacy
    Assert ($script:writes.Count -eq 0 -and $script:restarts -eq 0 -and $ctx.Results[0].Status -eq 'Skipped') 'Actual legacy engine dry run never writes or restarts even with planned prerequisites.'
    Reset;$script:decline=$true;$ctx=Context -Prompt;$outcome=Run $ctx
    Assert ($script:writes.Count -eq 0 -and $script:restarts -eq 0 -and $ctx.Results.Count -eq 3) 'Declined prerequisite blocks dependent changes.'
    Reset;$script:state.AuditMask=3;$script:state.Precedence=Reg 1;$script:writeAction={param($Name)if($Name -eq 'AuditFilter'){$script:state.AuditMask=0}};$ctx=Context;$outcome=Run $ctx
    Assert ($script:state.Filter.Value -eq 127 -and $script:restarts -eq 0 -and $ctx.Results[-1].Status -eq 'Failed') 'Prerequisite drift after filter write prevents restart and retains failure evidence.'
    Reset;$script:state.AuditMask=3;$script:state.Precedence=Reg 1;$script:readAction={if($script:reads -eq 6){$script:state.Active.Value='CA-B';$script:state.Path=$script:state.Path.Replace('CA-A','CA-B')}};$ctx=Context;$outcome=Run $ctx
    Assert ($script:restarts -eq 0 -and $ctx.Results[-1].Status -eq 'Failed') 'CA identity drift in immediate pre-restart read refuses restart.'
    Reset;$script:restartFail=$true;$ctx=Context;$outcome=Run $ctx;$done=Complete-WelaConfiguration $ctx
    Assert ($done.ExitCode -eq 1 -and $script:state.Filter.Value -eq 127 -and $outcome.Activation -eq 'RestartPending') 'Restart failure retains configured filter but never claims activation.'
    Reset;$ctx=Context;$outcome=Run $ctx;$script:state.Filter.Value=0;$done=Complete-WelaConfiguration $ctx
    Assert ($done.ExitCode -eq 1 -and @($done.Results|Where-Object Status -eq 'Failed').Count -eq 3) 'Final drift invalidates previously observed controls.'
    Reset;$script:state.AuditMask=3;$script:state.Precedence=Reg 1;$ctx=Context
    $ctx.Results.Add([pscustomobject]@{Id='AuditPolicy/Certification Services';Status='Failed';Kind='AuditPolicy'})
    Run $ctx -Legacy
    Assert ($script:writes.Count -eq 0 -and $script:restarts -eq 0 -and $ctx.Results[-1].Status -eq 'Failed') 'Earlier legacy prerequisite failure blocks CA writes even if a later sample matches.'
    Reset;$script:state.Status='NotApplicable';$ctx=Context;Run $ctx -Legacy
    Assert ($ctx.Results[0].Status -eq 'Skipped' -and $script:writes.Count -eq 0) 'Legacy non-CA remains a no-op.'
    Reset;$script:state.AuditMask=3;$script:state.Precedence=Reg 1;$script:state.Filter=Reg 127
    $json=Join-Path $temp 'report.json';$report=Invoke-WelaAdcsCommand -ResultsPath $json
    Assert ($report.PolicyState -eq 'PolicyMatches' -and $report.Activation -eq 'Unverified' -and $report.UsableRuleCredit -eq 0 -and $script:writes.Count -eq 0) 'Read-only public report preserves settings/activation/evidence distinctions.'
    Throws {Invoke-WelaAdcsCommand -ResultsPath $json} 'new local'
    Throws {Invoke-WelaAdcsCommand -Action Plan} 'explicit'
    Throws {Invoke-WelaAdcsCommand -AllowRestart} 'require AD CS Configure'
    $hash=(Get-FileHash -LiteralPath $json).Hash;$alias=Join-Path $temp 'alias.json';$null=New-Item -ItemType HardLink -Path $alias -Value $json
    Throws {Invoke-WelaAdcsCommand -ResultsPath $alias} 'new local'
    Assert ((Get-FileHash -LiteralPath $json).Hash -ceq $hash) 'Output aliases cannot overwrite previous evidence.'
    $badSource=Copy-State $source;$badSource.SchemaSha256='0'*64;Reset;$ctx=Context
    $outcome=Set-WelaAdcsControls $ctx $badSource (Copy-State $script:state) -ConfigurePrerequisites -AllowRestart
    Assert ($ctx.Results[0].Status -eq 'Failed' -and $script:writes.Count -eq 0) 'Changed source fingerprint is refused before writes.'
    # Delegate through the actual legacy wrapper; no alternate implementation.
    $script:delegated=$false
    function Invoke-WelaLegacyAdcsControl {param($Context)$script:delegated=$true}
    Set-WelaCertificateAuditControl (Context -DryRun)
    Assert $script:delegated 'Legacy helper invokes the same dedicated CA engine.'
    $exe=(Get-Process -Id $PID).Path
    foreach($arguments in @(@('configure','-AllowRestart'),@('configure','-AdcsProfile','microsoft-identity-ca-2026-09'),@('adcs-auditing','-Profile','wela-2.2.0'),@('adcs-auditing','-Role','ADCS'),@('adcs-auditing','-AdcsAction','Plan'))){
        $ErrorActionPreference='Continue';try{$output=&$exe -NoProfile -File (Join-Path $root 'WELA.ps1') @arguments 2>&1;$code=$LASTEXITCODE}finally{$ErrorActionPreference='Stop'}
        Assert ($code -ne 0 -and ($output -join ' ') -match 'No command|explicit -AdcsProfile') 'Actual CLI rejects unrelated controls, role overrides and absent source.'
    }
    $expected=[pscustomobject]@{Computer='CAHOST';RequestId=42;Requester='CAHOST\runner';Nonce='abc-123';StartUtc='2026-09-20T00:00:00Z';EndUtc='2026-09-20T00:01:00Z'}
    $xml='<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/><EventID>4886</EventID><Version>0</Version><Channel>Security</Channel><Computer>CAHOST</Computer><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="2026-09-20T00:00:01Z"/></System><EventData><Data Name="RequestId">42</Data><Data Name="Requester">CAHOST\runner</Data><Data Name="Attributes">WELAProbe:abc-123</Data></EventData></Event>'
    Assert (Test-WelaAdcsRequestEvent $xml $expected 4886) 'Exact native request event identity/context/outcome/nonce matches.'
    Assert (Test-WelaAdcsRequestEvent $xml.Replace('4886','4889') $expected 4889) 'Pending event is independently correlated to the same numeric request.'
    foreach($badXml in @($xml.Replace('>42<','>43<'),$xml.Replace('CAHOST</Computer>','OTHER</Computer>'),$xml.Replace('abc-123','other'),$xml.Replace('CAHOST\runner','CAHOST\other'),$xml.Replace('<Version>0','<Version>1'),$xml.Replace('0x8020000000000000','0x8010000000000000'),$xml.Replace('2026-09-20T00:00:01Z','2026-09-19T00:00:01Z'),$xml.Replace('</EventData>','<Data Name="RequestId">42</Data></EventData>'),('<!DOCTYPE Event [<!ENTITY x SYSTEM "file:///c:/secret">]>'+$xml))) {
        Assert (-not (Test-WelaAdcsRequestEvent $badXml $expected 4886)) 'Mismatched/ambiguous/unsafe request XML earns no native evidence.'
    }
    Write-Host "PASS: $script:count AD CS assertions; native writes and service restarts mocked."
}finally{Remove-Item -LiteralPath $temp -Recurse -Force}
$global:LASTEXITCODE=0
