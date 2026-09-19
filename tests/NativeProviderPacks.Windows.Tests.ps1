# Real provider/channel metadata only. No DNS requests, service/channel or policy changes.
param([string]$OutputDirectory)
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/NativeProviders.psm1') -Force
. (Join-Path $repo 'scripts/NativeProviderPacks.ps1')
$catalog=Get-WelaProviderPackCatalog
$count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
$before=@{}
foreach($pack in $catalog.packs){$before[$pack.channel]=Get-WelaNativeChannel -Name $pack.channel}
if(-not $OutputDirectory){$OutputDirectory=Join-Path ([IO.Path]::GetTempPath()) ('wela-provider-packs-'+[guid]::NewGuid().ToString('N'))}
$null=New-Item -ItemType Directory -Path $OutputDirectory -Force
$path=Join-Path $OutputDirectory 'provider-plan.json'
$shell=(Get-Process -Id $PID).Path
# PowerShell -File cannot reliably bind comma-separated native arguments to a
# string[] in every edition; invoke from a temporary PowerShell script instead.
$invoker=Join-Path $OutputDirectory 'invoke-read-only.ps1'
$escapedRepo=$repo.Replace("'","''");$escapedPath=$path.Replace("'","''")
@"
& '$escapedRepo/WELA.ps1' provider-packs -ProviderAction Plan -ProviderPack @('dns-client','dns-server-audit','dns-server-analytical','dns-server-classic','capi2','winrm','rdp-client') -ResultsPath '$escapedPath'
"@ | Set-Content -LiteralPath $invoker -Encoding UTF8
$oldPreference=$ErrorActionPreference;$ErrorActionPreference='Continue'
& $shell -NoProfile -File $invoker
$code=$LASTEXITCODE;$ErrorActionPreference=$oldPreference
$r=Get-Content -LiteralPath $path -Raw -ErrorAction Stop|ConvertFrom-Json
Assert ($code -eq $r.ExitCode -and $code -in @(0,1)) 'Real public CLI exit agrees with reported unavailable/manual prerequisites.'
Assert ($r.Action -eq 'Plan' -and $r.ControlsPlan.Count -eq 7 -and $r.ReadyRules -eq 0) 'Actual plan retains all selected packs and no readiness credit.'
Assert (@($r.ControlsPlan|Where-Object {$_.ProviderEvidence.Schema.State -eq 'Observed'}).Count -gt 0) 'At least one real Windows provider manifest must be read successfully.'
$dns=@($r.ControlsPlan|Where-Object {$_.Pack.id -eq 'dns-client'})[0]
Assert ($dns.RuleReviews.Count -eq 6 -and @($dns.RuleReviews|Where-Object {-not $_.ChannelMismatch}).Count -eq 0) 'Live report keeps the six full-definition DNS channel mismatches.'
foreach($entry in $r.ControlsPlan){
 $b=$before[$entry.Pack.channel];$a=Get-WelaNativeChannel -Name $entry.Pack.channel
 Assert ($b.State -eq $a.State -and $b.IsEnabled -eq $a.IsEnabled -and $b.MaximumSizeInBytes -eq $a.MaximumSizeInBytes -and $b.LogMode -eq $a.LogMode -and $b.SecurityDescriptor -ceq $a.SecurityDescriptor) 'Read-only smoke preserves each observed channel state, buffer, retention and ACL.'
 if($entry.ProviderEvidence.CanConfigure){
  Assert ($entry.ProviderEvidence.Schema.ChannelType -in @('Administrative','Operational')) 'A configurable pack has an actual safe channel type.'
  foreach($e in $entry.Pack.events){Assert (@($entry.ProviderEvidence.Schema.Events|Where-Object Id -eq $e.id).Count -gt 0) 'Actual event metadata belongs to the expected source/channel.'}
 }
}
Write-Host "PASS: $count real Windows provider-manifest/read-only CLI assertions. No native events were generated; field values/backend matching remain untested."
$global:LASTEXITCODE=0
