param([Parameter(Mandatory)][string]$RequestPath,[Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$RequestHash)
# Startup can reconstruct PSModulePath. Reset before any cmdlet/module can load.
$env:PSModulePath=[IO.Path]::Combine($PSHOME,'Modules')
$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$script:ScriptRoot=[IO.Path]::GetFullPath([IO.Path]::Combine($PSScriptRoot,'..'))
Import-Module (Join-Path $script:ScriptRoot 'modules/AuditProfiles.psm1') -ErrorAction Stop
Import-Module (Join-Path $script:ScriptRoot 'modules/WefSubscriptions.psm1') -ErrorAction Stop
foreach($name in @('WefArrival','WecUpdate','ChannelRead','WefQuery')){. (Join-Path $PSScriptRoot ($name+'.ps1'))}
$file=Read-WelaWecUpdateFile $RequestPath 2097152
if($file.Hash -cne $RequestHash){throw 'Query request hash differs.'};$request=ConvertFrom-WelaArrivalJson $file.Text
Assert-WelaArrivalObject $request @('SchemaVersion','Kind','Nonce','Query','QuerySha256','Channels','MaximumEvents','Sources','Host','Reader','Engine')
if(($request.SchemaVersion -isnot [int] -and $request.SchemaVersion -isnot [long]) -or $request.SchemaVersion -ne 1 -or $request.Kind -isnot [string] -or $request.Kind -cne 'WelaWefQueryRequest' -or $request.Nonce -isnot [string] -or $request.Nonce -cnotmatch '^[a-f0-9]{32}$' -or $request.Query -isnot [string] -or $request.QuerySha256 -isnot [string] -or $request.QuerySha256 -cne (Get-WelaArrivalHash ([Text.UTF8Encoding]::new($false).GetBytes($request.Query)))){throw 'Invalid native query request identity.'}
Assert-WelaWefQueryUInt $request.MaximumEvents
if($request.MaximumEvents -lt 1 -or $request.MaximumEvents -gt 64 -or $request.Query.Length -gt 65536){throw 'Native query request exceeds its bound.'}
$query=ConvertFrom-WelaWefQuery $request.Query
if($query.Filters.Count -gt 128 -or $query.Channels.Count -gt 16 -or (Get-WelaWefQueryKey @($query.Channels)) -cne (Get-WelaWefQueryKey $request.Channels)){throw 'Native query channel selection differs.'}
$hostState=Get-WelaWefQueryHost;$sources=Get-WelaWefQuerySources;$engine=Get-WelaWefQueryEngine;$before=Get-WelaWefQueryToken
if((Get-WelaWefQueryKey $hostState) -cne (Get-WelaWefQueryKey $request.Host) -or (Get-WelaWefQueryKey $sources) -cne (Get-WelaWefQueryKey $request.Sources) -or (Get-WelaWefQueryKey $engine) -cne (Get-WelaWefQueryKey $request.Engine) -or (Get-WelaWefQueryTokenKey $before) -cne (Get-WelaWefQueryTokenKey $request.Reader)){throw 'Worker actual context differs from request.'}
$started=[Wela.WefQueryToken.Native]::UtcNow()
$result=[Wela.WefQuery.Native]::Read($request.Query,$request.MaximumEvents)
$completed=[Wela.WefQueryToken.Native]::UtcNow();$after=Get-WelaWefQueryToken
if((Get-WelaWefQueryTokenKey $before) -cne (Get-WelaWefQueryTokenKey $after) -or (Read-WelaWecUpdateFile $RequestPath 2097152).Hash -cne $RequestHash -or (Get-WelaWefQueryKey (Get-WelaWefQuerySources)) -cne (Get-WelaWefQueryKey $sources)){throw 'Worker token, request or source changed during query.'}
[pscustomobject]@{SchemaVersion=1;Kind='WelaWefQueryWorker';Nonce=$request.Nonce;ProcessId=$PID;Engine=$engine;ModulePath=$env:PSModulePath;StartedUtc=$started.ToString('o');CompletedUtc=$completed.ToString('o');ReaderBefore=$before;ReaderAfter=$after;Host=$hostState;Sources=$sources;QuerySha256=$request.QuerySha256;Result=$result}|ConvertTo-Json -Depth 32 -Compress
exit 0
