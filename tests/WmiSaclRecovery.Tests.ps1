$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent;$script:ScriptRoot=$repo
Import-Module "$repo/modules/AuditProfiles.psm1" -Force
. "$repo/scripts/Configuration.ps1"
. "$repo/scripts/WmiNamespaceAuditing.ps1"
. "$repo/scripts/WmiProbe.ps1"
. "$repo/scripts/WefArrival.ps1"
. "$repo/scripts/WecUpdate.ps1"
. "$repo/scripts/WmiSaclRecovery.ps1"
$script:checks=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:checks++}
function Clone($Value){ConvertFrom-WelaArrivalJson (Get-WelaWmiRecoveryKey $Value)}
function Save($Path,$Value){[IO.File]::WriteAllText($Path,(Get-WelaWmiRecoveryKey $Value),[Text.UTF8Encoding]::new($false))}
function Reject([scriptblock]$Action){$failed=$false;try{&$Action|Out-Null}catch{$failed=$true};Assert $failed 'Unsupported or malformed evidence must be refused.'}
function Get-WelaWmiRecoveryContext {[pscustomobject][ordered]@{Host=[pscustomobject]@{Computer='TEST';Build=26100};TokenKey=$script:token;Policies='unchanged'}}
function Get-WelaWmiNamespaceSnapshot {
 param($Namespace)
 if($Namespace -cne 'root\default'){throw 'Unexpected fixture namespace'}
 [pscustomobject]@{Namespace=$Namespace;DescriptorJson=(ConvertTo-WelaWmiJson $script:descriptor);DescriptorMof='complete-native-fixture';SaclReadPrivilege='SeSecurityPrivilege enabled'}
}
function Set-WelaWmiNamespaceDescriptor {
 param($Namespace,$ExpectedJson,$Definitions)
 Assert ($ExpectedJson -ceq (ConvertTo-WelaWmiJson $script:descriptor)) 'Original production configuration supplies the exact current descriptor.'
 foreach($definition in $Definitions){
  $ace=[pscustomobject][ordered]@{AccessMask=[uint32]$definition.AccessMask;AceFlags=[uint32]$definition.AceFlags;AceType=2;GuidInheritedObjectType=$null;GuidObjectType=$null;Trustee=[pscustomobject]@{SIDString=$definition.Sid};TIME_CREATED=$null}
  $script:descriptor.SACL=@($script:descriptor.SACL|Where-Object {$null -ne $_})+@($ace)
 }
 $script:descriptor.ControlFlags=[uint32]$script:descriptor.ControlFlags -bor 16
 'Original fixture append succeeded.'
}
function Remove-WelaWmiRecoveryAce {
 param($Plan,$State)
 Assert (Test-Path (Join-Path $script:output 'pending.json')) 'Durable pending receipt precedes native removal.'
 $script:writes++;$State.WriteAttempted=$true
 if($script:scenario -eq 'native-failure'){throw 'Injected native failure'}
 if($script:scenario -ne 'false-success'){$script:descriptor=Get-WelaWmiRecoveryExpectedDescriptor $script:descriptor (Get-WelaWmiRecoveryKey $Plan.AddedAce)}
 if($script:scenario -eq 'empty-null'){$script:descriptor.SACL=$null}
 if($script:scenario -eq 'preservation'){$script:descriptor.Owner.SIDString='S-1-5-19'}
 if($script:scenario -eq 'token'){$script:token='changed'}
 if($script:scenario -eq 'last-history'){[IO.File]::AppendAllText($Plan.OriginalResults.Path,' ')}
 if($script:scenario -eq 'last-artifact'){[IO.File]::AppendAllText((Join-Path $script:output 'pending.json'),' ')}
 $State.After=Get-WelaWmiNamespaceSnapshot $Plan.Namespace
}
$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-wmi-recovery-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
$oldComputer=$env:COMPUTERNAME;$env:COMPUTERNAME='TEST'
function Original([string]$Directory,[switch]$Empty){
 $script:descriptor=Get-Content "$repo/tests/fixtures/wmi-namespace-descriptor.json" -Raw|ConvertFrom-Json
 if($Empty){$script:descriptor.SACL=$null}
 $script:token='original';$script:writes=0;$script:scenario=''
 $definitions=@(Get-WelaWmiAuditDefinitions -Namespace 'root\default')
 $entry=[pscustomobject]@{Namespace='root\default';Definitions=$definitions}
 $context=New-WelaConfigurationContext -Auto -BackupPath "$Directory/journal"
 Set-WelaWmiAuditControls $context @($entry)
 $r=Complete-WelaConfiguration $context -Scope 'wmi-namespace-sacl-only'
 Save "$Directory/original.json" $r
 Assert ($r.ExitCode -eq 0 -and $r.Results[0].Status -ceq 'Applied') 'Original journal and completed result come from actual shared configuration callbacks.'
}
try {
 foreach($case in @('ok','empty','empty-null','missing-consent','hash','tamper','duplicate-json','source','descriptor-drift','native-failure','false-success','preservation','token','last-history','last-artifact')){
  $dir=Join-Path $root $case;$null=New-Item -ItemType Directory $dir;Original $dir -Empty:($case -in @('empty','empty-null'))
  $plan=Invoke-WelaWmiSaclRecovery -Namespace 'root\default' -JournalPath "$dir/journal/before.jsonl" -OriginalResultsPath "$dir/original.json" -OutputPath "$dir/plan"
  Assert ($plan.Status -ceq 'ReviewRequired' -and $plan.ExitCode -eq 0) "Plan $case : $($plan.Diagnostic)"
  Assert ($script:writes -eq 0 -and -not $plan.WriteAttempted) 'Plan performs no native mutation.'
  $path="$dir/plan/plan.json";$hash=$plan.PlanHash
  if($case -eq 'hash'){$hash='f'*64}
  if($case -in @('tamper','duplicate-json')){
   $text=[IO.File]::ReadAllText($path)
   $text=if($case -eq 'tamper'){$text.Replace('audit ACE','unexpected ACE')}else{$text.Replace('"SchemaVersion":1,','"SchemaVersion":1,"SchemaVersion":1,')}
   [IO.File]::WriteAllText($path,$text);$hash=(Get-FileHash $path).Hash.ToLowerInvariant()
  }
  if($case -eq 'source'){[IO.File]::AppendAllText("$dir/original.json",' ')}
  if($case -eq 'descriptor-drift'){$script:descriptor.Group.SIDString='S-1-5-19'}
  $script:scenario=$case;$script:output="$dir/recover"
  $result=Invoke-WelaWmiSaclRecovery Recover -PlanPath $path -PlanHash $hash -OutputPath $script:output -AllowAuditReduction:($case -ne 'missing-consent')
  Assert (($result.ExitCode -eq 0) -eq ($case -in @('ok','empty','empty-null'))) "Recover $case : $($result.Diagnostic)"
  Assert ($result.ReadyRuleCredit -eq 0 -and $result.PolicyChanges -eq 0 -and (Test-Path "$dir/recover/manifest.json")) 'Recovery reports no event/policy/Sigma credit and retains outcome evidence.'
  if($case -in @('ok','empty','empty-null')){
   Assert ($result.Status -ceq 'AddedAceRemoved' -and $result.WriteAttempted -and $script:writes -eq 1) 'Successful recovery removes one proven ACE once.'
   Assert (@(Get-WelaWmiMissingAces $script:descriptor @(Get-WelaWmiAuditDefinitions -Namespace 'root\default')).Count -eq 1) 'The original proven addition is absent after recovery.'
   $again=Invoke-WelaWmiSaclRecovery Recover -PlanPath $path -PlanHash $hash -OutputPath "$dir/replay" -AllowAuditReduction
   Assert ($again.Status -ceq 'Refused' -and $script:writes -eq 1) 'Completed recovery cannot be replayed against an already changed descriptor.'
  }elseif($case -in @('native-failure','false-success','preservation','token','last-history','last-artifact')){
   Assert ($result.Status -ceq 'WriteAttemptedUnverified' -and $result.WriteAttempted -and $script:writes -eq 1) 'Possible mutation is never reported as a pre-write refusal or verified recovery.'
  }else{Assert ($result.Status -ceq 'Refused' -and -not $result.WriteAttempted -and $script:writes -eq 0) 'Stale, malformed, unconsented or drifted input cannot write.'}
  foreach($artifact in $result.Artifacts){$valid=(Get-FileHash (Join-Path $result.OutputPath $artifact.Name)).Hash.ToLowerInvariant() -ceq $artifact.Sha256;Assert ($valid -eq (-not ($case -eq 'last-artifact' -and $artifact.Name -ceq 'pending.json'))) 'Artifact hashes reflect actual saved bytes, including deliberate tampering.'}
 }
 $dir=Join-Path $root 'history';$null=New-Item -ItemType Directory $dir;Original $dir
 $savedResult=[IO.File]::ReadAllText("$dir/original.json");$savedJournal=[IO.File]::ReadAllText("$dir/journal/before.jsonl")
 foreach($bad in @('failed','dryrun','wrong-host','future','duplicate-row','duplicate-journal','wrong-kind','desired-inheritance','target','incomplete','changed-owner','removed-other','extra-addition','ambiguous-addition','unknown-added-field','false-privilege','string-flags','null-ace','propagation-control')){
  $r=ConvertFrom-WelaArrivalJson $savedResult;$e=ConvertFrom-WelaArrivalJson $savedJournal
  switch($bad){
   'failed' {$r.Results[0].Status='Failed'}
   'dryrun' {$r.DryRun=$true}
   'wrong-host' {$e.ComputerName='OTHER'}
   'future' {$e.RecordedUtc=[DateTime]::UtcNow.AddDays(1).ToString('o')}
   'duplicate-row' {$r.Results+=,$r.Results[0]}
   'wrong-kind' {$r.Results[0].Kind='Other'}
   'desired-inheritance' {$r.Results[0].Desired[0].AceFlags=66;$e.Desired=Clone $r.Results[0].Desired}
   'target' {$r.Results[0].Target.Operation='Replace descriptor';$e.Target=Clone $r.Results[0].Target}
   'incomplete' {$r.Results[0].Before.PSObject.Properties.Remove('DescriptorMof');$e.Before=Clone $r.Results[0].Before}
   'false-privilege' {$r.Results[0].Before.SaclReadPrivilege='Not enabled';$e.Before=Clone $r.Results[0].Before}
   default {
    $d=ConvertFrom-WelaArrivalJson $r.Results[0].After.DescriptorJson
    switch($bad){
     'changed-owner' {$d.Owner.SIDString='S-1-5-19'}
     'removed-other' {$d.SACL=@($d.SACL|Select-Object -Skip 1)}
     'extra-addition' {$d.SACL+=,(Clone $d.SACL[0])}
     'ambiguous-addition' {$d.SACL+=,(Clone $d.SACL[-1])}
     'unknown-added-field' {$d.SACL[-1]|Add-Member NoteProperty Unknown 'unsafe'}
     'string-flags' {$d.ControlFlags=[string]$d.ControlFlags}
     'null-ace' {$d.SACL+=,$null}
     'propagation-control' {$d.ControlFlags=[int]$d.ControlFlags -bor 512}
    }
    $r.Results[0].After.DescriptorJson=Get-WelaWmiRecoveryKey $d
   }
  }
  Save "$dir/original.json" $r;$text=Get-WelaWmiRecoveryKey $e;if($bad -eq 'duplicate-journal'){$text+="`n"+$text};[IO.File]::WriteAllText("$dir/journal/before.jsonl",$text)
  $p=Invoke-WelaWmiSaclRecovery -Namespace 'root\default' -JournalPath "$dir/journal/before.jsonl" -OriginalResultsPath "$dir/original.json" -OutputPath "$dir/reject-$bad"
  Assert ($p.Status -ceq 'Refused' -and -not $p.WriteAttempted) "Original $bad refused: $($p.Diagnostic)"
 }
 foreach($args in @(@{Namespace='root\*'},@{Namespace='\\remote\root\default'},@{Namespace='root\default';AllowAuditReduction=$true},@{Action='Recover';PlanHash='bad';PlanPath='absent'})){
  Reject {Invoke-WelaWmiSaclRecovery @args -OutputPath "$dir/unused"}
 }
}finally{$env:COMPUTERNAME=$oldComputer;Remove-Item -LiteralPath $root -Recurse -Force}
Write-Host "PASS: $script:checks WMI recovery proof, consent, preservation, replay and partial-outcome assertions. Native behavior is tested separately."
