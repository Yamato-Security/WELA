param([switch]$AllowDisposableLoggingWrite)
$ErrorActionPreference='Stop'
if(-not $AllowDisposableLoggingWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Explicit opt-in on disposable GitHub-hosted Windows is required.'}
$repo=Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/PowerShellLogging.ps1')
Import-Module (Join-Path $repo 'modules/AuditProfiles.psm1') -Force
$root=Join-Path $env:RUNNER_TEMP ('wela-powershell-logging-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
$engine=(Get-Process -Id $PID).Path;$script:count=0;$failure=$null;$cleanupErrors=@();$original=$null;$prepared=$null;$masks=$null;$workerPath=$null;$mutationStarted=$false
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Save($Name,$Value){$Value|ConvertTo-Json -Depth 28|Set-Content -LiteralPath (Join-Path $root $Name) -Encoding UTF8}
function Masks {$m=Get-WelaEffectiveAuditPolicy;@($m.Keys|Sort-Object|ForEach-Object{"$_=$($m[$_])"}) -join ';'}
Add-Type -TypeDefinition @'
using System;using System.IO;using System.Text;using System.Threading.Tasks;using System.Runtime.InteropServices;
public static class WelaPsLoggingFixture {
 [DllImport("kernel32.dll")] static extern void GetSystemTimePreciseAsFileTime(out long value);
 public static DateTime Now(){long value;GetSystemTimePreciseAsFileTime(out value);return DateTime.FromFileTimeUtc(value);}
 public static async Task<string> Read(TextReader reader){var text=new StringBuilder();var buffer=new char[1024];while(true){int n=await reader.ReadAsync(buffer,0,buffer.Length).ConfigureAwait(false);if(n==0)return text.ToString();if(n>1048576-text.Length)throw new InvalidDataException("Owned child output exceeds one Mi character bound.");text.Append(buffer,0,n);}}
}
'@
function Child([string]$Label,[string]$Executable,[string[]]$Arguments){
    foreach($a in $Arguments){if($a.Contains('"') -or $a.EndsWith('\') -or $a -match '[\x00-\x1f]'){throw 'Ambiguous fixture process argument.'}}
    $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$Executable;$info.Arguments=(@($Arguments|ForEach-Object{'"'+$_+'"'}) -join ' ');$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $p=[Diagnostics.Process]::new();$p.StartInfo=$info;$started=$false
    try{
        $start=[WelaPsLoggingFixture]::Now();if(-not $p.Start()){throw 'Child did not start.'};$started=$true;$ownedId=$p.Id
        $stdout=[WelaPsLoggingFixture]::Read($p.StandardOutput);$stderr=[WelaPsLoggingFixture]::Read($p.StandardError)
        if(-not $p.WaitForExit(180000)){throw 'Owned child exceeded three minutes.'};$end=[WelaPsLoggingFixture]::Now()
        if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout,$stderr),5000)){throw 'Owned child output drain timed out.'}
        $receipt=[pscustomobject]@{Executable=$Executable;Arguments=$info.Arguments;Pid=$ownedId;StartedUtc=$start.ToString('o');ExitedUtc=$end.ToString('o');ExitCode=$p.ExitCode;Output=$stdout.Result;Error=$stderr.Result}
        Save ($Label+'-process.json') $receipt;return $receipt
    }finally{if($started -and -not $p.HasExited){$p.Kill();if(-not $p.WaitForExit(5000)){throw 'Owned child exit could not be confirmed; cleanup may be incomplete.'}};$p.Dispose()}
}
$wrapper=Join-Path $root 'public.ps1'
@'
param([string]$Repository,[string]$Request)
$ErrorActionPreference='Stop'
$data=Get-Content -LiteralPath $Request -Raw|ConvertFrom-Json;$options=@{}
foreach($property in $data.PSObject.Properties){$options[$property.Name]=$property.Value}
$global:LASTEXITCODE=0
& (Join-Path $Repository 'WELA.ps1') @options
exit $LASTEXITCODE
'@ | Set-Content -LiteralPath $wrapper -Encoding UTF8
function Public([string]$Label,[hashtable]$Parameters,[int]$ExpectedExit=0){
    $Parameters.Cmd='powershell-logging';$Parameters.ResultsPath=Join-Path $root ($Label+'.json');$request=Join-Path $root ($Label+'-request.json');$Parameters|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $request -Encoding UTF8
    $process=Child $Label $engine @('-NoLogo','-NoProfile','-NonInteractive','-File',$wrapper,'-Repository',$repo,'-Request',$request)
    Assert (($process.ExitCode -eq 0) -eq ($ExpectedExit -eq 0)) "Public $Label unexpected exit $($process.ExitCode): $($process.Output) $($process.Error)"
    if(Test-Path -LiteralPath $Parameters.ResultsPath){return Get-Content -Raw -LiteralPath $Parameters.ResultsPath|ConvertFrom-Json};throw 'Public report missing.'
}
function RestoreValue($Tree,[string]$Path,[string]$Name){
    $originalValue=Get-WelaPsLoggingValue $Tree $Path $Name;$base=$null;$key=$null
    try{$base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64);$key=$base.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows\PowerShell\'+$Path,$true);if($originalValue){if(-not $key){throw 'Original policy key disappeared.'};$value=$originalValue.Value;if($originalValue.Type -eq 'DWord'){$value=[int]$value};if($originalValue.Type -eq 'QWord'){$value=[long]$value};if($originalValue.Type -eq 'Binary'){$value=[byte[]]$value};if($originalValue.Type -eq 'MultiString'){$value=[string[]]$value};$key.SetValue($Name,$value,[Microsoft.Win32.RegistryValueKind]::$($originalValue.Type));$key.Flush()}elseif($key){$key.DeleteValue($Name,$false);$key.Flush()}}
    finally{if($key){$key.Dispose()};if($base){$base.Dispose()}}
}
function RemoveCreatedKeys($Tree){
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    try{foreach($path in @('ModuleLogging\ModuleNames','ScriptBlockLogging','ModuleLogging','')){
        if(@($Tree.Keys|Where-Object Path -ieq $path).Count){continue};$full='SOFTWARE\Policies\Microsoft\Windows\PowerShell';if($path){$full+='\'+$path};$key=$null
        try{$key=$base.OpenSubKey($full,$false);if(-not $key){continue};if($key.ValueCount -or $key.SubKeyCount){throw "Created key is no longer empty: $full"}}finally{if($key){$key.Dispose()}}
        $base.DeleteSubKey($full,$false)
    }}finally{$base.Dispose()}
}
function ReadEvents([int]$OwnedId,[long]$Watermark){
    $query="*[System[(EventID=4103 or EventID=4104) and Execution[@ProcessID='$OwnedId'] and EventRecordID > $Watermark]]"
    $q=[Diagnostics.Eventing.Reader.EventLogQuery]::new('Microsoft-Windows-PowerShell/Operational',[Diagnostics.Eventing.Reader.PathType]::LogName,$query);$q.TolerateQueryErrors=$false
    $reader=$null;$list=New-Object 'System.Collections.Generic.List[string]'
    try{$reader=[Diagnostics.Eventing.Reader.EventLogReader]::new($q);for($i=0;$i -le 64;$i++){$record=$reader.ReadEvent([TimeSpan]::FromSeconds(2));if(-not $record){break};try{$xml=$record.ToXml();if($xml.Length -gt 262144){throw 'Owned child event exceeds XML bound.'};$list.Add($xml)}finally{$record.Dispose()};if($i -eq 64){throw 'Owned child event candidate cap exceeded.'}};$statuses=@($reader.LogStatus);if($statuses.Count -ne 1 -or $statuses[0].LogName -cne 'Microsoft-Windows-PowerShell/Operational' -or $statuses[0].StatusCode -ne 0){throw 'Native query must report exactly one complete successful expected channel.'};return @($list.ToArray())}finally{if($reader){$reader.Dispose()}}
}
try{
    $original=Get-WelaPsLoggingSnapshot;Save 'original.json' $original;$masks=Masks
    Assert ($original.Host.ProductType -eq 3 -and $original.Host.DomainRole -eq 2 -and -not $original.Host.PartOfDomain -and -not $original.Host.CertSvcPresent) 'Fixture requires a standalone disposable non-CA server.'
    Assert $original.Channel.Enabled 'Existing PowerShell operational channel must already be enabled.'
    $protected=@($original.ProtectedEventLogging.Keys|ForEach-Object {$_.Values}|Where-Object {$_.Name -eq 'EnableProtectedEventLogging' -and $_.Value -ne 0})
    Assert ($protected.Count -eq 0) 'Protected logging must not obscure this plaintext event fixture.'
    # Test fixture only: prepare explicit disabled values; production has no disable action.
    $mutationStarted=$true
    foreach($pair in @(@('ModuleLogging','EnableModuleLogging'),@('ScriptBlockLogging','EnableScriptBlockLogging'))){
        $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64);$key=$null
        try{$key=$base.CreateSubKey('SOFTWARE\Policies\Microsoft\Windows\PowerShell\'+$pair[0]);$key.SetValue($pair[1],0,[Microsoft.Win32.RegistryValueKind]::DWord);$key.Flush()}finally{if($key){$key.Dispose()};$base.Dispose()}
    }
    $selectedName=Get-WelaPsLoggingValue $original.Machine 'ModuleLogging\ModuleNames' 'Microsoft.PowerShell.Utility'
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64);$key=$null
    try{$key=$base.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames',$true);if($key){$key.DeleteValue('Microsoft.PowerShell.Utility',$false);$key.Flush()}}finally{if($key){$key.Dispose()};$base.Dispose()}
    $prepared=Get-WelaPsLoggingSnapshot;Save 'prepared.json' $prepared
    $audit=Public audit @{};Assert ($audit.ExitCode -eq 0 -and $audit.ReadyRuleCredit -eq 0) 'Unselected public Audit is observational.'
    $plan=Public plan @{PowerShellLoggingAction='Plan';PowerShellLoggingControl=@('Module','ScriptBlock');PowerShellLoggingModuleName=@('Microsoft.PowerShell.Utility')}
    Assert (@($plan.Plan.Controls|Where-Object Status -eq ChangeRequired).Count -eq 3) 'Public plan contains three exact value changes.'
    $dry=Public dry @{PowerShellLoggingAction='Configure';PowerShellLoggingControl=@('Module','ScriptBlock');PowerShellLoggingModuleName=@('Microsoft.PowerShell.Utility');DryRun=$true;BackupPath=(Join-Path $root 'dry-backup')}
    Assert ($dry.Skipped -eq 3 -and -not (Test-Path (Join-Path $root 'dry-backup'))) 'Public dry run writes neither policy nor backup.'
    Assert ((ConvertTo-WelaPsLoggingKey (Get-WelaPsLoggingSnapshot)) -ceq (ConvertTo-WelaPsLoggingKey $prepared)) 'Audit/Plan/DryRun preserve the complete prepared snapshot.'
    $apply=Public configure @{PowerShellLoggingAction='Configure';PowerShellLoggingControl=@('Module','ScriptBlock');PowerShellLoggingModuleName=@('Microsoft.PowerShell.Utility');Auto=$true;BackupPath=(Join-Path $root 'configure-backup')}
    Assert ($apply.ExitCode -eq 0 -and @($apply.Results|Where-Object Status -eq Applied).Count -eq 3) 'Public Configure applies three named values.'
    $journal=@(Get-Content -LiteralPath (Join-Path $root 'configure-backup/before.jsonl')|ForEach-Object{$_|ConvertFrom-Json});Assert ($journal.Count -eq 3) 'Each native write has its own original journal.'
    Assert ((ConvertTo-WelaPsLoggingKey $journal[0].Before) -ceq (ConvertTo-WelaPsLoggingKey $prepared)) 'First journal matches exact typed prepared state.'
    $configured=Get-WelaPsLoggingSnapshot;Save 'configured.json' $configured
    $again=Public repeat @{PowerShellLoggingAction='Configure';PowerShellLoggingControl=@('Module','ScriptBlock');PowerShellLoggingModuleName=@('Microsoft.PowerShell.Utility');Auto=$true;BackupPath=(Join-Path $root 'repeat-backup')}
    Assert (@($again.Results|Where-Object Status -eq AlreadyCompliant).Count -eq 3 -and -not (Test-Path (Join-Path $root 'repeat-backup/before.jsonl'))) 'Second Configure makes no native writes.'
    Assert ((ConvertTo-WelaPsLoggingKey (Get-WelaPsLoggingSnapshot)) -ceq (ConvertTo-WelaPsLoggingKey $configured)) 'Repeated configuration preserves complete observed state.'
    $nonce='WELA_PS_LOG_'+[guid]::NewGuid().ToString('N');$workerPath=Join-Path $root ('worker-'+[guid]::NewGuid().ToString('N')+'.ps1')
    $workerText="Microsoft.PowerShell.Utility\Write-Output -InputObject '$nonce'`n"
    [IO.File]::WriteAllText($workerPath,$workerText,[Text.UTF8Encoding]::new($false));Save 'worker-source.json' @{Path=$workerPath;Sha256=(Get-FileHash $workerPath -Algorithm SHA256).Hash;Text=$workerText;Nonce=$nonce}
    $latest=Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 1 -ErrorAction Stop;try{$watermark=[long]$latest.RecordId}finally{$latest.Dispose()}
    $process=Child 'event-worker' $configured.Engine.Path @('-NoLogo','-NoProfile','-NonInteractive','-File',$workerPath)
    Assert ($process.ExitCode -eq 0 -and $process.Output.Trim() -ceq $nonce) 'Fixed native Windows PowerShell child executed the benign marker.'
    $selected=@{};$candidates=@();$timer=[Diagnostics.Stopwatch]::StartNew()
    do{
        $candidates=@(ReadEvents $process.Pid $watermark);$selected=@{}
        foreach($xml in $candidates){
            $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=262144;$xmlReader=[Xml.XmlReader]::Create([IO.StringReader]::new($xml),$settings)
            try{$doc=[Xml.XmlDocument]::new();$doc.XmlResolver=$null;$doc.PreserveWhitespace=$true;$doc.Load($xmlReader)}finally{$xmlReader.Dispose()};$ns=[Xml.XmlNamespaceManager]::new($doc.NameTable);$ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event');$system=$doc.SelectSingleNode('/e:Event/e:System',$ns);$data=@{}
            foreach($node in $doc.SelectNodes('/e:Event/e:EventData/e:Data',$ns)){if($data.ContainsKey($node.GetAttribute('Name'))){throw 'Duplicate native event field.'};$data[$node.GetAttribute('Name')]=$node.InnerText}
            $id=[int]$system.SelectSingleNode('e:EventID',$ns).InnerText
            if($system.SelectSingleNode('e:Provider',$ns).GetAttribute('Name') -cne 'Microsoft-Windows-PowerShell' -or $system.SelectSingleNode('e:Provider',$ns).GetAttribute('Guid').Trim('{}') -ine 'a0c1853b-5c40-4b15-8766-3cf1c58f985a' -or [int]$system.SelectSingleNode('e:Execution',$ns).GetAttribute('ProcessID') -ne $process.Pid -or $system.SelectSingleNode('e:Channel',$ns).InnerText -cne 'Microsoft-Windows-PowerShell/Operational' -or $system.SelectSingleNode('e:Computer',$ns).InnerText -ine $env:COMPUTERNAME){continue}
            $time=[DateTimeOffset]::Parse($system.SelectSingleNode('e:TimeCreated',$ns).GetAttribute('SystemTime')).UtcDateTime;if($time -lt [DateTimeOffset]::Parse($process.StartedUtc).UtcDateTime -or $time -gt [DateTimeOffset]::Parse($process.ExitedUtc).UtcDateTime){continue}
            if($system.SelectSingleNode('e:Security',$ns).GetAttribute('UserID') -cne $original.Operator.Sid){continue}
            if($id -eq 4104 -and $data.ScriptBlockText -ceq $workerText -and $data.Path -ieq $workerPath -and $data.MessageNumber -ceq '1' -and $data.MessageTotal -ceq '1' -and $data.ScriptBlockId -match '^[0-9a-f-]{36}$'){$selected['4104']=@($selected['4104'])+ $xml}
            if($id -eq 4103 -and $data.ContainsKey('Payload') -and $data.ContainsKey('ContextInfo') -and $data.Payload.Contains($nonce) -and $data.ContextInfo.Contains($workerPath)){$selected['4103']=@($selected['4103'])+ $xml}
        }
        if(@($selected['4103']|Where-Object {$_}).Count -eq 1 -and @($selected['4104']|Where-Object {$_}).Count -eq 1){break};Start-Sleep -Milliseconds 200
    }while($timer.Elapsed.TotalSeconds -lt 15)
    Save 'event-candidates.json' $candidates
    foreach($id in @('4103','4104')){$events=@($selected[$id]|Where-Object {$_});Assert ($events.Count -eq 1) "Exactly one worker-attributed native $id event required; found $($events.Count).";[IO.File]::WriteAllText((Join-Path $root ('event-'+$id+'.xml')),$events[0],[Text.UTF8Encoding]::new($false))}
    Assert ((ConvertTo-WelaPsLoggingKey (Get-WelaPsLoggingSnapshot)) -ceq (ConvertTo-WelaPsLoggingKey $configured)) 'Fresh event probe changes no policy or channel state.'
    Assert ((Masks) -ceq $masks) 'All 59 audit masks remain unchanged.'
    # Wrong-type selected value is refused by the public command without repairing it.
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64);$key=$null
    try{$key=$base.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging',$true);$key.SetValue('EnableScriptBlockLogging','1',[Microsoft.Win32.RegistryValueKind]::String)}finally{if($key){$key.Dispose()};$base.Dispose()}
    $wrong=Get-WelaPsLoggingSnapshot;$refused=Public wrong-type @{PowerShellLoggingAction='Configure';PowerShellLoggingControl=@('ScriptBlock');Auto=$true;BackupPath=(Join-Path $root 'wrong-backup')} 1
    Assert ($refused.ExitCode -eq 1 -and -not (Test-Path (Join-Path $root 'wrong-backup'))) 'Wrong-type preflight refuses before backup or writes.'
    Assert ((ConvertTo-WelaPsLoggingKey (Get-WelaPsLoggingSnapshot)) -ceq (ConvertTo-WelaPsLoggingKey $wrong)) 'Refusal preserves the typed wrong value.'
}catch{$failure=$_.ToString();Save 'failure.json' @{Error=$failure;Stack=$_.ScriptStackTrace}}
finally{
    if($original -and $mutationStarted){
        foreach($item in @(@('ScriptBlockLogging','EnableScriptBlockLogging'),@('ModuleLogging','EnableModuleLogging'),@('ModuleLogging\ModuleNames','Microsoft.PowerShell.Utility'))){try{RestoreValue $original.Machine $item[0] $item[1]}catch{$cleanupErrors+=$_.ToString()}}
        try{RemoveCreatedKeys $original.Machine}catch{$cleanupErrors+=$_.ToString()}
        try{$after=Get-WelaPsLoggingSnapshot;Save 'cleanup-after.json' $after;if((ConvertTo-WelaPsLoggingKey $after) -cne (ConvertTo-WelaPsLoggingKey $original)){$cleanupErrors+='Full policy/host/source/channel snapshot did not restore exactly.'};if($masks -and (Masks) -cne $masks){$cleanupErrors+='Audit masks changed.'}}catch{$cleanupErrors+=$_.ToString()}
    }
    Save 'cleanup.json' @{Status=$(if($cleanupErrors.Count){'Failed'}elseif($mutationStarted){'Restored'}else{'NotMutated'});Errors=$cleanupErrors;OriginalCaptured=[bool]$original;MutationStarted=$mutationStarted;All59MasksUnchanged=($masks -and (Masks) -ceq $masks)}
    $artifacts=@(Get-ChildItem -LiteralPath $root -File -Recurse|ForEach-Object{[pscustomobject]@{Path=$_.FullName.Substring($root.Length+1);Sha256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}})
    Save 'manifest.json' @{Kind='WelaPowerShellLoggingNativeFixture';Head=$env:GITHUB_SHA;Engine=$PSVersionTable.PSVersion.ToString();Assertions=$script:count;Failure=$failure;CleanupErrors=$cleanupErrors;ReadyRuleCredit=0;Artifacts=$artifacts}
}
if($failure -or $cleanupErrors.Count){throw "Native fixture failed: $failure Cleanup: $($cleanupErrors -join '; ')"}
Write-Host "PASS: $script:count public PowerShell policy/native4103/native4104 assertions with exact cleanup."
