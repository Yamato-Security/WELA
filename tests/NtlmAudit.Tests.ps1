$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/NtlmAudit.ps1')
$hostValidator=${function:Get-WelaNtlmAuditHost}
$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-ntlm-audit-tests-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
$count=0;$sequence=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Key($Value){ConvertTo-Json -InputObject $Value -Depth 18 -Compress}
function Copy-Fixture($Value){Key $Value|ConvertFrom-Json}
function Reset($Incoming=0,$Domain=0,[switch]$Dc){
 $script:hostState=[pscustomobject][ordered]@{Computer='fixture';Domain=$(if($Dc){'fixture.test'}else{'WORKGROUP'});Build=26100;ProductType=$(if($Dc){2}else{3});DomainRole=$(if($Dc){4}else{2});PartOfDomain=[bool]$Dc}
 $script:policies=@{};foreach($pair in @(@('Incoming',$Incoming),@('Domain',$Domain))){$script:policies[$pair[0]]=[pscustomobject][ordered]@{KeyExists=$true;ValueExists=($null -ne $pair[1]);Value=$pair[1];Type=$(if($null -eq $pair[1]){$null}else{'DWord'})}}
 $script:writes=@();$script:reads=@{Incoming=0;Domain=0};$script:readFail='';$script:writeFail='';$script:ignore='';$script:promptChange=$null;$script:onRead=$null
}
function Get-WelaNtlmAuditHost {Copy-Fixture $script:hostState}
function Get-WelaNtlmAuditPolicySource {[pscustomobject]@{Status='Unknown';Diagnostic='Fixture has no policy ownership evidence.'}}
function Get-WelaRegistryState {param($Path,$Name)
 $selection=switch($Name){AuditReceivingNTLMTraffic{'Incoming'} AuditNTLMInDomain{'Domain'} default {throw 'Unexpected read'}}
 $definition=Get-WelaNtlmAuditDefinition $selection;if($Path -cne $definition.Path){throw 'Unexpected registry path'}
 $script:reads[$selection]++;if($script:onRead){& $script:onRead $selection}
 if($script:readFail -eq $selection){throw 'Injected read denied'}
 Copy-Fixture $script:policies[$selection]
}
function Set-ItemProperty {param($LiteralPath,$Name,$Value,$Type,$ErrorAction)
 $selection=switch($Name){AuditReceivingNTLMTraffic{'Incoming'} AuditNTLMInDomain{'Domain'} default {throw 'Unexpected mutation'}}
 $definition=Get-WelaNtlmAuditDefinition $selection
 Assert ($LiteralPath -ceq $definition.Path -and $Value -eq $definition.Value -and $Type -ceq 'DWord') 'Only the selected exact audit value may be changed.'
 $script:writes+=@($selection);if($script:writeFail -eq $selection){throw 'Injected write denied'}
 if($script:ignore -ne $selection){$script:policies[$selection].ValueExists=$true;$script:policies[$selection].Value=$Value;$script:policies[$selection].Type='DWord'}
}
function Read-Host {param($Prompt) if($script:promptChange){& $script:promptChange};return 'Y'}
function Configure($Selection='Incoming',[switch]$DryRun,[switch]$Prompt){
 $script:sequence++;$script:backup=Join-Path $root ('case-'+$script:sequence)
 Invoke-WelaNtlmAuditCommand -Action Configure -Selection $Selection -Auto:(-not $Prompt) -DryRun:$DryRun -BackupPath $script:backup
}
try{
 foreach($initial in @($null,0,1,2)){
  Reset -Incoming $initial;$old=Key $script:policies.Incoming;$r=Configure
  Assert ($r.ExitCode -eq 0 -and $r.Scope -ceq 'incoming-domain-ntlm-audit-policy-only' -and $r.ReadyRuleCredit -eq 0) 'Success is explicitly limited to selected audit policies.'
  Assert ($script:policies.Incoming.Value -eq 2 -and $script:writes.Count -eq $(if($initial -eq 2){0}else{1}) -and $script:reads.Domain -eq 0) 'Incoming scope preserves domain policy and enables only auditing.'
  if($initial -ne 2){$j=@(Get-Content (Join-Path $backup 'before.jsonl')|ConvertFrom-Json);Assert ($j.Count -eq 1 -and (Key $j[0].Before.Policy) -ceq $old) 'Journal retains exact typed original before one write.'}
  else{Assert ($r.Results[0].Status -ceq 'AlreadyCompliant' -and -not(Test-Path (Join-Path $backup 'before.jsonl'))) 'Existing all-account auditing is idempotent.'}
 }
 foreach($initial in @($null,0,1,2,3,5,7)){
  Reset -Domain $initial -Dc;$r=Configure Domain
  Assert ($r.ExitCode -eq 0 -and $script:policies.Domain.Value -eq 7 -and $script:reads.Incoming -eq 0) 'Actual-DC domain selection requests only full domain auditing.'
  if($initial -eq 2){Assert ($r.Plan.Controls[0].Status -ceq 'LegacyValue2' -and $r.Plan.Controls[0].Diagnostic -match 'undocumented') 'Legacy2 is identified without assigning it invented semantics.'}
 }
 foreach($selection in @('Incoming','Domain')){
  $values=if($selection -eq 'Incoming'){@(3,42,'1',$true)}else{@(4,6,8,'7',$true)}
  foreach($invalid in $values){
   Reset -Dc;$script:policies[$selection].Value=$invalid;$r=Configure $selection
   Assert ($r.ExitCode -eq 1 -and $r.Results[0].Status -ceq 'Failed' -and $script:writes.Count -eq 0) 'Unknown numeric values and coerced strings/bools fail without mutation.'
  }
  Reset -Dc;$script:policies[$selection].Type='String';$r=Configure $selection
  Assert ($r.ExitCode -eq 1 -and $script:writes.Count -eq 0) 'Unknown registry type fails without mutation.'
  Reset -Dc;$script:policies[$selection].KeyExists=$false;$r=Configure $selection
  Assert ($r.ExitCode -eq 1 -and $script:writes.Count -eq 0) 'Missing policy parents are never created.'
  Reset -Dc;$script:readFail=$selection;$r=Configure $selection
  Assert ($r.ExitCode -eq 1 -and $script:writes.Count -eq 0) 'Access-denied is not fabricated absence.'
 }
 foreach($selection in @('Domain','Both')){
  Reset;$r=Configure $selection
  $domain=@($r.Results|Where-Object {$_.Target.Name -eq 'AuditNTLMInDomain'})
  Assert ($r.ExitCode -eq 0 -and $domain.Count -eq 1 -and $domain[0].Status -ceq 'Skipped' -and $script:reads.Domain -eq 0 -and $script:writes -notcontains 'Domain') 'Non-DC domain audit is explicitly not applicable with no read or write.'
 }
 Reset -Dc;$r=Configure Both;Assert ($r.ExitCode -eq 0 -and $script:writes.Count -eq 2 -and @($r.Results|Where-Object Status -ne 'Applied').Count -eq 0) 'Both scopes produce separate applied rows on a coherent DC.'
 Reset -Dc;$script:writeFail='Domain';$r=Configure Both;Assert ($r.ExitCode -eq 1 -and $r.Results[0].Status -ceq 'Applied' -and $r.Results[1].Status -ceq 'Failed') 'A partial failure preserves each distinct result and nonzero status.'
 Reset -Dc;$r=Configure Both -DryRun;Assert ($script:writes.Count -eq 0 -and $r.DryRun -and -not(Test-Path $backup)) 'Dry-run creates neither policy mutations nor journal directory.'
 Reset;$script:ignore='Incoming';$r=Configure;Assert ($r.ExitCode -eq 1 -and $r.Results[0].Status -ceq 'Failed') 'An ignored native write fails immediate verification.'
 foreach($changed in @(1,2,42)){
  Reset;$script:changed=$changed;$script:promptChange={$script:policies.Incoming.Value=$script:changed};$r=Configure -Prompt
  Assert ($r.ExitCode -eq 1 -and $script:writes.Count -eq 0) 'Prompt-time value drift refuses mutation after preserving the original snapshot.'
 }
 Reset;$script:promptChange={$script:hostState.Computer='different-host'};$r=Configure -Prompt
 Assert ($r.ExitCode -eq 1 -and $script:writes.Count -eq 0) 'Prompt-time host drift refuses mutation.'
 Reset;$script:onRead={param($s)if($s -eq 'Incoming' -and $script:reads.Incoming -eq 5){$script:policies.Incoming.Value=0}};$r=Configure
 Assert ($r.ExitCode -eq 1 -and $r.Results[0].Status -ceq 'Overridden') 'Later policy override fails final readback.'
 Reset;$r=Invoke-WelaNtlmAuditCommand -Action Plan;Assert ($r.Plan.Controls.Count -eq 2 -and $script:writes.Count -eq 0) 'Default assessment reports both distinct controls without mutation.'
 $refused=$false;try{Invoke-WelaNtlmAuditCommand -Action Configure}catch{$refused=$true};Assert $refused 'The library requires explicit Configure selection.'
 foreach($action in @('Audit','Plan')){foreach($option in @('Auto','DryRun','BackupPath')){
  $args=@{Action=$action};$args[$option]=$(if($option -eq 'BackupPath'){'unused'}else{$true});$refused=$false;try{Invoke-WelaNtlmAuditCommand @args}catch{$refused=$true};Assert $refused 'Read-only actions reject mutation-only options.'
 }}
 # Exercise actual CIM role validation independently of the policy fixture.
 $savedOs=$env:OS;$env:OS='Windows_NT'
 function Get-CimInstance {param($ClassName,$Property,$ErrorAction)if($ClassName -eq 'Win32_OperatingSystem'){$script:osFixture}else{$script:computerFixture}}
 try{
  foreach($case in @(@(1,0,$false,26100),@(1,1,$true,26200),@(3,2,$false,20348),@(3,3,$true,26100),@(2,4,$true,20348),@(2,5,$true,26100))){
   $script:osFixture=[pscustomobject]@{ProductType=$case[0];BuildNumber=[string]$case[3]};$script:computerFixture=[pscustomobject]@{Name='fixture';Domain='fixture';DomainRole=$case[1];PartOfDomain=$case[2]};$h=&$hostValidator;Assert ($h.ProductType -eq $case[0]) 'Coherent native role/build accepted.'
  }
  foreach($case in @(@(2,2,$false,26100),@(3,4,$true,26100),@(1,1,$false,26100),@(3,3,$false,26100),@(2,5,$true,99999))){
   $script:osFixture=[pscustomobject]@{ProductType=$case[0];BuildNumber=[string]$case[3]};$script:computerFixture=[pscustomobject]@{Name='fixture';Domain='fixture';DomainRole=$case[1];PartOfDomain=$case[2]};$refused=$false;try{&$hostValidator}catch{$refused=$true};Assert $refused 'Conflicting or unsupported observed host is refused.'
  }
 }finally{$env:OS=$savedOs}
}finally{Remove-Item -LiteralPath $root -Recurse -Force}
Write-Host "PASS: $count scoped incoming/domain NTLM assertions."
exit 0
