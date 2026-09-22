param([Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$Nonce)
$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$script:ScriptRoot=Split-Path $PSScriptRoot -Parent
. "$PSScriptRoot/WefArrival.ps1"
. "$PSScriptRoot/ChannelRead.ps1"
. "$PSScriptRoot/FailedLogonProbe.ps1"
Initialize-WelaFailedLogonNative
foreach($name in @('EventLog','Winmgmt','SamSs','RpcSs')){if((Get-Service -Name $name -ErrorAction Stop).Status -ne 'Running'){throw 'Required native services must already be running.'}}
$hostState=Get-WelaChannelReadHost
if($hostState.ProductType -notin @(1,3) -or $hostState.DomainRole -notin @(0,1,2,3)){throw 'A local SAM client or member/standalone server is required.'}
$before=Get-WelaChannelReader
$result=[Wela.FailedLogonProbe.Native]::Run($Nonce)
$after=Get-WelaChannelReader
[pscustomobject][ordered]@{Nonce=$Nonce;ProcessId=$PID;Executable=(Get-Process -Id $PID).Path;BeforeToken=$before;AfterToken=$after;Attempt=$result}|ConvertTo-Json -Depth 10 -Compress
