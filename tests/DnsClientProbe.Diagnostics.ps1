# Temporary native ABI diagnostic: called only inside the explicitly gated owned DNS fixture.
param([ValidateRange(0,4)][int]$Variant)
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:OS -ne 'Windows_NT'){throw 'Disposable native fixture only.'}
$source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot '../scripts/DnsClientProbeNative.cs'))
# Keep the fixed product query name/options and explicit loopback resolver. Vary only server buffer ABI.
$variants=@(@(1,0,0),@(96,0,0),@(1,2,0),@(1,0,53),@(96,2,53))
$v=$variants[$Variant]
$source=$source.Replace('BitConverter.GetBytes((uint)1).CopyTo(server,0);',('BitConverter.GetBytes((uint)'+$v[0]+').CopyTo(server,0);BitConverter.GetBytes((ushort)'+$v[1]+').CopyTo(server,12);server[35]='+$v[2]+';'))
Add-Type -TypeDefinition $source
[pscustomobject]@{Variant=$Variant;MaxCount=$v[0];Family=$v[1];Port=$v[2];Result=[Wela.DnsClientProbe.Native]::Query(('wela-'+[guid]::NewGuid().ToString('N')+'.wela.test.'),'127.0.0.1')}|ConvertTo-Json -Depth 8 -Compress
