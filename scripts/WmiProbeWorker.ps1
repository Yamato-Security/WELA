# Fixed local query worker, isolated so an unresponsive provider can be terminated.
param([Parameter(Mandatory)][string]$Namespace)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
. (Join-Path $PSScriptRoot 'WmiProbe.ps1')
Assert-WelaWmiProbeNamespace $Namespace
Initialize-WelaWmiProbeNative
if((Get-Service -Name Winmgmt -ErrorAction Stop).Status -ne 'Running'){throw 'Winmgmt is not running; no WMI connection was attempted.'}
Add-Type -AssemblyName System.Management -ErrorAction Stop
$before=[Wela.WmiProbe.Native]::Snapshot()
$nonce='WelaReadProbe_'+[guid]::NewGuid().ToString('N')
$query="SELECT Name FROM __Namespace WHERE Name='$nonce'"
$options=New-Object System.Management.ConnectionOptions
$options.EnablePrivileges=$false
$options.Impersonation=[System.Management.ImpersonationLevel]::Impersonate
$options.Timeout=[TimeSpan]::FromSeconds(10)
$scope=New-Object System.Management.ManagementScope -ArgumentList ('\\.\'+$Namespace),$options
$searcher=$null;$rows=$null
$started=[DateTime]::UtcNow
try {
    $scope.Connect()
    $enumeration=New-Object System.Management.EnumerationOptions
    $enumeration.Timeout=[TimeSpan]::FromSeconds(10);$enumeration.ReturnImmediately=$true;$enumeration.Rewindable=$false
    $searcher=New-Object System.Management.ManagementObjectSearcher -ArgumentList $scope,([System.Management.ObjectQuery]::new($query)),$enumeration
    $rows=$searcher.Get();$count=0
    foreach($row in $rows){try{$count++;if($count -gt 0){throw 'The random nonexistent namespace filter unexpectedly matched an instance.'}}finally{$row.Dispose()}}
    $completed=[DateTime]::UtcNow
    $after=[Wela.WmiProbe.Native]::Snapshot()
    if((Get-WelaWmiProbeTokenKey $before) -cne (Get-WelaWmiProbeTokenKey $after)){throw 'Worker token changed during the fixed query.'}
    [pscustomobject]@{Namespace=$Namespace;Query=$query;ExpectedAccessMask=1;ProcessId=$PID;StartedUtc=$started.ToString('o');CompletedUtc=$completed.ToString('o');BeforeToken=$before;AfterToken=$after;ReturnedRows=$count;Operation='Fixed local read; provider completion is separate from audited namespace access'}|ConvertTo-Json -Depth 10 -Compress
}finally{if($rows){$rows.Dispose()};if($searcher){$searcher.Dispose()}}
