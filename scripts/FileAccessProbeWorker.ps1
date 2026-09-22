param([Parameter(Mandatory)][string]$RequestPath,[Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$Nonce)
$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if($args.Count){throw 'Unexpected file worker arguments.'}
$script:ScriptRoot=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $script:ScriptRoot 'modules/AuditProfiles.psm1') -ErrorAction Stop
foreach($name in @('Configuration','WefArrival','ChannelRead','WmiProbe','FileAccessProbe')){. (Join-Path $PSScriptRoot ($name+'.ps1'))}
Initialize-WelaFileProbeNative
$requestFile=Get-Item -LiteralPath (Resolve-WelaArrivalPath $RequestPath) -ErrorAction Stop
if($requestFile.Length -gt 1048576){throw 'File worker request exceeds one MiB.'}
$state=ConvertFrom-WelaArrivalJson ([IO.File]::ReadAllText($requestFile.FullName,[Text.UTF8Encoding]::new($false,$true)))
$null=Get-WelaFileProbeStateKey $state
$fresh=Get-WelaFileProbeState $state.File.Path
if((Get-WelaFileProbeStateKey $fresh) -cne (Get-WelaFileProbeStateKey $state)){throw 'Host, caller, source, file or audit prerequisites changed before worker access.'}
$handle=[Wela.FileAccessProbe.FileHandle]::new($state.File.Path,$true)
try {
    if($handle.Observe().StateKey -cne $state.File.StateKey){throw 'Selected file changed before worker read.'}
    $beforeReader=Get-WelaChannelReader;$beforeToken=[Wela.WmiProbe.Native]::Snapshot()
    if((Get-WelaFileProbeTokenKey $beforeToken) -cne (Get-WelaFileProbeTokenKey $state.Token) -or (Get-WelaFileProbeReaderKey $beforeReader -AuthorizationOnly) -cne (Get-WelaFileProbeKey $state.Reader)){throw 'Worker does not preserve the expected caller token.'}
    $read=$handle.ReadOne($state.File.StateKey)
    $afterToken=[Wela.WmiProbe.Native]::Snapshot();$afterReader=Get-WelaChannelReader
    [pscustomobject]@{Kind='WelaOneByteFileRead';Nonce=$Nonce;ProcessId=$PID;Executable=(Get-Process -Id $PID).Path;FilePath=$state.File.Path;BeforeReader=$beforeReader;AfterReader=$afterReader;BeforeToken=$beforeToken;AfterToken=$afterToken;Read=$read}|ConvertTo-Json -Depth 16 -Compress
}finally{$handle.Dispose()}
