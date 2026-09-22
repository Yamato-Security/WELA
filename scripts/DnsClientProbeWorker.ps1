param([Parameter(Mandatory)][string]$Resolver,[Parameter(Mandatory)][string]$QueryName)
$ErrorActionPreference='Stop';$script:ScriptRoot=Split-Path $PSScriptRoot -Parent
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
. (Join-Path $PSScriptRoot 'WefArrival.ps1')
. (Join-Path $PSScriptRoot 'ChannelRead.ps1')
. (Join-Path $PSScriptRoot 'DnsClientProbe.ps1')
Initialize-WelaDnsClientProbeNative
if((Get-Service Dnscache -ErrorAction Stop).Status -ne 'Running'){throw 'DNS Client must already be running.'}
$before=Get-WelaChannelReader
$start=[Wela.DnsClientProbe.Native]::UtcNow().ToString('o')
$query=[Wela.DnsClientProbe.Native]::Query($QueryName,$Resolver)
$end=[Wela.DnsClientProbe.Native]::UtcNow().ToString('o')
$after=Get-WelaChannelReader
if((Get-WelaChannelReadKey $before) -cne (Get-WelaChannelReadKey $after)){throw 'Worker primary token changed during DNS query.'}
[pscustomobject]@{Query=$query;StartedUtc=$start;CompletedUtc=$end;Clock='GetSystemTimePreciseAsFileTime';ProcessId=$PID;BeforeToken=$before;AfterToken=$after}|ConvertTo-Json -Depth 12 -Compress
