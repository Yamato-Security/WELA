# Fixed native5.1 worker. Automatic policy is the sole transcription producer.
param([Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$Nonce)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if($PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or -not [Environment]::Is64BitProcess){throw 'Native Windows PowerShell5.1 is required.'}
$script:ScriptRoot=Split-Path $PSScriptRoot -Parent
. (Join-Path $PSScriptRoot 'WmiProbe.ps1')
. (Join-Path $PSScriptRoot 'PowerShellTranscription.ps1')
Initialize-WelaWmiProbeNative
$assembly=[psobject].Assembly
$types=@($assembly.GetTypes()|Where-Object Name -eq 'InternalHostUserInterfaceStrings')
if($types.Count -ne 1){throw 'Native transcript resource type is unknown.'}
$resources=[ordered]@{}
foreach($name in @('TranscriptPrologue','TranscriptEpilogue')){
    $property=$types[0].GetProperty($name,[Reflection.BindingFlags]'Public,NonPublic,Static')
    if(-not $property){throw 'Native transcript resource is unavailable.'}
    $value=$property.GetValue($null,$null)
    if($value -isnot [string] -or $value.Length -gt 8192 -or -not $value.Contains('{0:yyyyMMddHHmmss}')){throw 'Unrecognized native transcript resource.'}
    $resources[$name]=$value
}
$assemblyPath=$assembly.Location;$assemblyHash=(Get-FileHash -LiteralPath $assemblyPath -Algorithm SHA256).Hash.ToLowerInvariant()
$policyBefore=@(Get-WelaTranscriptPolicy @('Registry64','Registry32'));Test-WelaTranscriptSharedPolicy $policyBefore
$before=[Wela.WmiProbe.Native]::Snapshot();$start=[DateTimeOffset]::Now
Microsoft.PowerShell.Utility\Write-Output ('WELA-TRANSCRIPT-BEGIN:'+${Nonce}+':'+$PID)
$policyAfter=@(Get-WelaTranscriptPolicy @('Registry64','Registry32'))
if(($policyBefore|ConvertTo-Json -Depth 12 -Compress) -cne ($policyAfter|ConvertTo-Json -Depth 12 -Compress)){throw 'Worker policy changed.'}
if((Get-FileHash -LiteralPath $assemblyPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $assemblyHash){throw 'Worker engine assembly changed.'}
$after=[Wela.WmiProbe.Native]::Snapshot()
if((Get-WelaWmiProbeTokenKey $before) -cne (Get-WelaWmiProbeTokenKey $after)){throw 'Worker token changed.'}
Microsoft.PowerShell.Utility\Write-Output ('WELA-TRANSCRIPT-END:'+${Nonce}+':'+$PID)
$end=[DateTimeOffset]::Now
$operation=[pscustomobject][ordered]@{
    Nonce=$Nonce;ProcessId=$PID;Engine=(Get-Process -Id $PID).Path;EngineVersion=$PSVersionTable.PSVersion.ToString();Edition=$PSVersionTable.PSEdition
    StartedUtc=$start.UtcDateTime.ToString('o');CompletedUtc=$end.UtcDateTime.ToString('o');StartOffsetMinutes=$start.Offset.TotalMinutes;EndOffsetMinutes=$end.Offset.TotalMinutes
    BeforeToken=$before;AfterToken=$after;PolicyBefore=$policyBefore;PolicyAfter=$policyAfter
    Computer=[Environment]::MachineName;HeaderUser=([Environment]::UserDomainName+'\'+[Environment]::UserName);OsVersion=[Environment]::OSVersion.VersionString
    CommandLine=[Environment]::CommandLine;Arguments=@([Environment]::GetCommandLineArgs());UiCulture=[Globalization.CultureInfo]::CurrentUICulture.Name
    Assembly=[pscustomobject]@{Path=$assemblyPath;FullName=$assembly.FullName;Sha256=$assemblyHash};Resources=[pscustomobject]$resources
}
[Console]::WriteLine('WELA-WORKER-JSON:'+($operation|ConvertTo-Json -Depth 16 -Compress))
