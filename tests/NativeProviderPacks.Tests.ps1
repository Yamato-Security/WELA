# Synthetic provider manifests and shared native writer boundary; no Windows changes.
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/EventLogSettings.psm1') -Force
Import-Module (Join-Path $repo 'modules/NativeProviders.psm1') -Force
Import-Module (Join-Path $repo 'modules/NativeChannelAccess.psm1') -Force
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/NativeChannelConfiguration.ps1')
. (Join-Path $repo 'scripts/NativeProviderPacks.ps1')
$script:ScriptRoot=$repo
$script:count=0;$script:cleanup=@()
function Assert($Value,$Message) { if (-not $Value) {throw $Message};$script:count++ }
function Throws($Action,$Message) { $failed=$false;try {& $Action | Out-Null}catch {$failed=$true};Assert $failed $Message }
function Reset {
 $script:f=@{}
 $script:catalog=Get-WelaProviderPackCatalog
 $script:f=@{States=@{};Writes=@();Role='Client';Build=26100;Service='Running';Type='Operational';TemplateMode='good';NativeFailure='';Prompt='Y';PromptSchemaDrift=$false;ProviderReads=0;DriftAt=0}
 foreach($pack in $catalog.packs){$f.States[$pack.channel]=[pscustomobject]@{Name=$pack.channel;State='Disabled';IsEnabled=$false;MaximumSizeInBytes=[long]1048576;LogMode='Retain';SecurityDescriptor='unchanged';ProviderNames=@($pack.provider);MetadataErrors=@{};Error=$null}}
 $script:backup=Join-Path ([IO.Path]::GetTempPath()) ('wela-packs-'+[guid]::NewGuid().ToString('N'));$script:cleanup+=,$backup
}
function Get-WelaHostContext { if($f.Role -eq 'Unknown'){throw 'denied'};[pscustomobject]@{Role=$f.Role;Build=$f.Build} }
function Get-WelaNativeService { param($Name) [pscustomobject]@{Name=$Name;State=$f.Service;Error=$null} }
function Get-WelaNativeChannel { param($Name) $f.States[$Name].PSObject.Copy() }
function Get-FileHash {
 param($LiteralPath,$Algorithm)
 if(($f.BadPin -eq 'corpus' -and $LiteralPath -like '*security_rules.json') -or ($f.BadPin -eq 'rule' -and $LiteralPath -like '*.yml')){return [pscustomobject]@{Hash=('0'*64)}}
 Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $LiteralPath -Algorithm $Algorithm
}
function Test-WelaChannelDescriptorEqual {param($First,$Second) $First -ceq $Second}
function Get-WelaChannelAccessPlan {param($SecurityDescriptor) [pscustomobject]@{State='GrantRequired';ProposedDescriptor='must-not-write';Diagnostic='Fixture only';EffectiveReadAccess='Not tested'}}
function Get-WinEvent {
 param($ListLog,$ListProvider,$ErrorAction)
 if($ListLog){$p=@($catalog.packs|Where-Object channel -eq $ListLog)[0];return [pscustomobject]@{LogName=$ListLog;LogType=$f.Type;ProviderNames=@($p.provider)}}
 $f.ProviderReads++
 if($f.DriftAt -eq $f.ProviderReads){$f.TemplateMode='missing'}
 if($f.TemplateMode -eq 'denied'){throw 'Provider access denied'}
 $p=@($catalog.packs|Where-Object provider -eq $ListProvider)[0]
 $events=@()
 foreach($e in $p.events){
  $template='<template xmlns="http://schemas.microsoft.com/win/2004/08/events"><data name="QueryName" inType="win:UnicodeString"/><data name="QNAME" inType="win:UnicodeString"/></template>'
  if($f.TemplateMode -eq 'missing'){$template='<template/>'}
  if($f.TemplateMode -eq 'wrongtype'){$template=$template.Replace('win:UnicodeString','win:UInt32')}
  $channel=if($f.TemplateMode -eq 'wrongchannel'){'Other/Operational'}else{$p.channel}
  $events+= [pscustomobject]@{Id=$e.id;Version=0;LogLink=[pscustomobject]@{LogName=$channel};Template=$template}
 }
 [pscustomobject]@{Name=$ListProvider;Id='11111111-1111-1111-1111-111111111111';LogLinks=@([pscustomobject]@{LogName=$p.channel});Events=$events}
}
function Read-Host {param($Prompt) if($f.PromptSchemaDrift){$f.TemplateMode='missing'};$f.Prompt}
function Invoke-WelaNative {
 param($FilePath,$Arguments)
 Assert ($FilePath -eq 'wevtutil.exe' -and $Arguments[0] -eq 'sl') 'Only existing native channel settings may change.'
 Assert (Test-Path (Join-Path $backup 'before.jsonl')) 'Recovery journal precedes every native write.'
 Assert (($Arguments -join ' ') -notmatch '/ca:|/rt:|/ab:') 'Provider packs never change permissions or retention.'
 $f.Writes+=,@($Arguments)
 if($f.NativeFailure -eq 'throw'){throw 'fixture native error'}
 if($f.NativeFailure -eq 'nochange'){return}
 foreach($a in $Arguments){if($a -eq '/e:true'){$f.States[$Arguments[1]].IsEnabled=$true;$f.States[$Arguments[1]].State='Enabled'};if($a -like '/ms:*'){$f.States[$Arguments[1]].MaximumSizeInBytes=[long]$a.Substring(4)}}
}
$oldOS=$env:OS
try {
 $env:OS='Windows_NT';Reset
 # Exercise the real import boundary: a same-named test stub must not hide a
 # missing export used by the public provider-pack script.
 $nativeModule=Get-Module NativeProviders
 Assert ($nativeModule.ExportedCommands.ContainsKey('Get-WelaNativeService')) 'Service observations required by packs are exported to the calling script.'
 & $nativeModule {
  $script:packServiceFixture='Running'
  function script:Get-Service {
   [CmdletBinding()]param($Name)
   if($script:packServiceFixture -eq 'Absent'){$PSCmdlet.ThrowTerminatingError([Management.Automation.ErrorRecord]::new([Exception]::new('No such service'),'NoServiceFoundForGivenName','ObjectNotFound',$Name))}
   if($script:packServiceFixture -eq 'Denied'){throw [UnauthorizedAccessException]::new('Service read denied')}
   [pscustomobject]@{Status=$script:packServiceFixture}
  }
 }
 try {
  foreach($pair in @(@('Running','Running'),@('Absent','Not installed'),@('Denied','Unknown'))) {
   & $nativeModule {param($value) $script:packServiceFixture=$value} $pair[0]
   $service=NativeProviders\Get-WelaNativeService -Name DNS
   Assert ($service.Name -eq 'DNS' -and $service.State -eq $pair[1]) 'Public service reader distinguishes installed, absent and denied observations without leaking an error.'
  }
 } finally {& $nativeModule {Remove-Item Function:\Get-Service}}
 Assert ($catalog.packs.Count -eq 7 -and $catalog.ruleReviews.Count -eq 15) 'Seven explicit packs retain fifteen pinned full native rule definitions.'
 $list=Invoke-WelaProviderPackCommand
 Assert ($list.ReadyRules -eq 0 -and $f.ProviderReads -eq 0) 'List is definitions only, with no host reads or detection credit.'
 foreach($pin in @('corpus','rule')){Reset;$f.BadPin=$pin;Throws {Invoke-WelaProviderPackCommand -Action Configure -Names dns-client -Auto -BackupPath $backup} 'Changed pinned corpus/full-rule bytes block configuration before planning.';Assert ($f.Writes.Count -eq 0 -and -not(Test-Path $backup)) 'Pin failure cannot write channels or create a journal.'}
 Reset
 Throws {Invoke-WelaProviderPackCommand -Action Plan} 'No default selection can activate all packs.'
 Throws {Invoke-WelaProviderPackCommand -Action Plan -Names '*' } 'Wildcard pack selection is rejected.'
 Throws {Invoke-WelaProviderPackCommand -Action Plan -Names @('dns-client','dns-client')} 'Duplicate selection is rejected.'
 Throws {Invoke-WelaProviderPackCommand -Action Audit -Names dns-client -DryRun} 'DryRun is valid only for configuration.'
 $report=Invoke-WelaProviderPackCommand -Action Plan -Names dns-client
 $entry=$report.ControlsPlan[0]
 Assert ($entry.Status -eq 'ChangeRequired' -and $entry.ProviderEvidence.CanConfigure) 'Exact local manifest and required string fields can support channel configuration.'
 Assert ($entry.RuleReviews.Count -eq 6 -and @($entry.RuleReviews|Where-Object {-not $_.ChannelMismatch}).Count -eq 0) 'All six DNS rules retain the upstream channel mismatch, without silent aliasing.'
 Assert (@($entry.RuleReviews|Where-Object Eligibility -ne 'Conditional').Count -eq 0 -and $report.ReadyRules -eq 0) 'Provider settings never convert incomplete rule evidence into Ready.'
 Assert ($entry.ProviderEvidence.Schema.Events[0].Fields[0].InType -eq 'win:UnicodeString' -and $entry.ProviderEvidence.Schema.Events[0].TemplateSha256.Length -eq 64) 'Report retains runtime version, native field types and template fingerprint.'
 Assert ($f.Writes.Count -eq 0 -and -not(Test-Path $backup)) 'Read-only plan creates no journal and makes no channel changes.'
 Reset;$f.States['Microsoft-Windows-DNS-Client/Operational'].State='Not installed';$f.States['Microsoft-Windows-DNS-Client/Operational'].IsEnabled=$null
 $r=Invoke-WelaProviderPackCommand -Action Configure -Names dns-client -Auto -BackupPath $backup
 Assert ($r.ExitCode -eq 1 -and $f.Writes.Count -eq 0) 'Missing actual channel metadata cannot be replaced by provider-manifest availability.'
 foreach($mode in @('missing','wrongtype','wrongchannel','denied')){
  Reset;$f.TemplateMode=$mode;$r=Invoke-WelaProviderPackCommand -Action Configure -Names dns-client -Auto -BackupPath $backup
  Assert ($r.ExitCode -eq 1 -and $f.Writes.Count -eq 0) "Schema $mode cannot be configured."
 }
 foreach($type in @('Analytical','Debug','Unknown')){
  Reset;$f.Type=$type;$r=Invoke-WelaProviderPackCommand -Action Configure -Names dns-client -Auto -BackupPath $backup
  Assert ($r.ExitCode -eq 1 -and $f.Writes.Count -eq 0) "Runtime channel type $type blocks writes."
 }
 foreach($role in @('Unknown','Client')){
  Reset;$f.Role=$role;$f.Build=99999;$r=Invoke-WelaProviderPackCommand -Action Plan -Names dns-client
  Assert ($r.ExitCode -eq 1 -and -not $r.ControlsPlan[0].ProviderEvidence.CanConfigure) 'Unknown roles/builds cannot be assumed supported.'
 }
 Reset;$f.Role='DomainController';$f.Service='Not installed';$r=Invoke-WelaProviderPackCommand -Action Plan -Names dns-server-audit
 Assert ($r.ExitCode -eq 1) 'DC membership does not substitute for an installed DNS Server role.'
 foreach($name in @('dns-server-classic','dns-server-analytical')){
  Reset;$f.Role='MemberServer';$r=Invoke-WelaProviderPackCommand -Action Configure -Names $name -Auto -BackupPath $backup
  Assert ($r.ExitCode -eq 1 -and $f.Writes.Count -eq 0) 'Classic and Analytical DNS packs remain manual-only even with a matching fixture registration.'
 }
 Reset;$r=Invoke-WelaProviderPackCommand -Action Configure -Names dns-client -DryRun -BackupPath $backup
 Assert ($r.DryRun -and $f.Writes.Count -eq 0 -and -not(Test-Path $backup)) 'DryRun rechecks prerequisites but never changes channels or creates a recovery journal.'
 Reset;$r=Invoke-WelaProviderPackCommand -Action Configure -Names dns-client -Auto -BackupPath $backup
 Assert ($r.ExitCode -eq 0 -and $r.Results[0].Status -eq 'Applied' -and $f.Writes.Count -eq 1) 'Explicit selected channel is journaled and verified by the shared runner.'
 Assert ($r.Results[0].After.IsEnabled -and $r.ReadyRules -eq 0) 'Verified channel enablement remains separate from telemetry readiness.'
 $again=$backup+'-again';$cleanup+=,$again;$r=Invoke-WelaProviderPackCommand -Action Configure -Names dns-client -Auto -BackupPath $again
 Assert ($r.Results[0].Status -eq 'AlreadyCompliant' -and $f.Writes.Count -eq 1) 'Repeated configuration is idempotent.'
 Reset;$f.Role='MemberServer';$r=Invoke-WelaProviderPackCommand -Action Configure -Names @('dns-client','dns-server-classic') -Auto -BackupPath $backup
 Assert ($r.ExitCode -eq 1 -and $f.Writes.Count -eq 1 -and @($r.Results|Where-Object Status -eq 'Failed').Count -eq 1) 'A manual-only selection stays failed while an independent supported selection completes.'
 Reset;$f.States['Microsoft-Windows-DNS-Client/Operational'].MaximumSizeInBytes=[long]4294967296
 $r=Invoke-WelaProviderPackCommand -Action Configure -Names dns-client -Auto -BackupPath $backup
 Assert ($r.Results[0].After.MaximumSizeInBytes -eq 4294967296 -and $r.Results[0].After.LogMode -eq 'Retain') 'Larger buffers and retention survive an enablement request.'
 Reset;$r=Invoke-WelaProviderPackCommand -Action Configure -Names capi2 -Auto -BackupPath $backup
 Assert ($r.ControlsPlan[0].Definition.sourceExampleBytes -eq 102432768 -and -not $r.ControlsPlan[0].Desired.AccessChangeRequested) 'CAPI2 reuses the exact existing profile and leaves reader ACL changes for channel-settings.'
 foreach($failure in @('throw','nochange')){Reset;$f.NativeFailure=$failure;$r=Invoke-WelaProviderPackCommand -Action Configure -Names dns-client -Auto -BackupPath $backup;Assert ($r.ExitCode -eq 1) 'Native failure or false success cannot produce a verified configuration.'}
 Reset;$f.Prompt='n';$r=Invoke-WelaProviderPackCommand -Action Configure -Names dns-client -BackupPath $backup
 Assert ($r.Skipped -eq 1 -and $f.Writes.Count -eq 0) 'Operator decline is preserved.'
 Reset;$f.PromptSchemaDrift=$true;$r=Invoke-WelaProviderPackCommand -Action Configure -Names dns-client -BackupPath $backup
 Assert ($r.ExitCode -eq 1 -and $f.Writes.Count -eq 0) 'Schema changes after the prompt are refused before the native write.'
 Reset;$f.DriftAt=5;$r=Invoke-WelaProviderPackCommand -Action Configure -Names dns-client -Auto -BackupPath $backup
 Assert ($r.ExitCode -eq 1 -and $r.Results[0].Diagnostic -like '*Final verification*') 'Final provider-schema drift changes the overall outcome to failure.'
 Throws {Get-WelaProviderTemplateFields '<!DOCTYPE x [<!ENTITY y SYSTEM "file:///etc/passwd">]><template>&y;</template>'} 'Native template parser refuses DTD/entity expansion.'
 Throws {Get-WelaProviderTemplateFields '<template><data name="a"/><data name="a"/></template>'} 'Ambiguous template field names are refused.'
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'WELA.ps1'),[ref]$tokens,[ref]$errors)
 Assert ($errors.Count -eq 0) 'Combined public CLI parses.'
 $nodes=@($ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.IfStatementAst] -and ($_.Extent.Text -match 'Provider options require' -or $_.Extent.Text -match 'Invoke-WelaProfileCommand -Command')})
 Assert ($nodes.Count -eq 2) 'Provider option guard and profile dispatch are both retained.'
 $dispatch=[scriptblock]::Create('param($Cmd,$Profile,$ProviderAction,$ProviderPack)'+[Environment]::NewLine+(($nodes|ForEach-Object {$_.Extent.Text})-join [Environment]::NewLine))
 function Invoke-WelaProfileCommand {throw 'UNSAFE: profile dispatcher was reached'}
 foreach($option in @('ProviderAction','ProviderPack')) { $args=@{Cmd='configure';Profile='wela'};$args[$option]='fixture';$caught=$null;try{& $dispatch @args}catch{$caught=$_.ToString()};Assert ($caught -like '*Provider options require*') 'Dedicated options are rejected before an unrelated profile could change policy.' }
 Write-Host "PASS: $count native provider pack assertions; synthetic manifests only, no Windows changes."
} finally {$env:OS=$oldOS;foreach($path in $cleanup){if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Recurse -Force}}}
