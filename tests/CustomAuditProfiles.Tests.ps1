$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$script:ScriptRoot=$root
Import-Module (Join-Path $root 'modules/AuditProfiles.psm1') -Force
. (Join-Path $root 'scripts/Configuration.ps1')
$script:count=0
function Assert($Condition,$Message) { if (-not $Condition) { throw $Message }; $script:count++ }
function Throws($Action,$Pattern) { $message=''; try { & $Action | Out-Null } catch { $message=$_.Exception.Message }; Assert ($message -match $Pattern) "Expected $Pattern; got $message" }
function Copy-Fixture($Object) { $Object | ConvertTo-Json -Depth 20 | ConvertFrom-Json }
$sample=Get-Content -LiteralPath (Join-Path $root 'config/custom-audit-profile.example.json') -Raw | ConvertFrom-Json
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-custom-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
$script:file=Join-Path $temp 'profile.json'
function Save($Value=$sample) { $Value | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $script:file -Encoding UTF8 }
function Bad($Edit,$Pattern) { $value=Copy-Fixture $sample; & $Edit $value; Save $value; Throws {Import-WelaCustomAuditProfiles $script:file} $Pattern }
try {
    Save
    $data=Import-WelaCustomAuditProfiles $script:file
    Assert ($data.catalog.Count -eq 59 -and $data.customSource.Sha256.Length -eq 64 -and $data.customSource.Provenance -match 'Operator-declared') 'Custom references resolve to full authoritative catalog and exact-byte provenance.'
    Assert (($data.catalog | Where-Object id -eq 'File System').prerequisites -match 'SACL') 'Custom file cannot erase canonical SACL prerequisites.'
    $script:zero=@{}; foreach ($row in $data.catalog) {$script:zero[$row.guid]=0}
    $process=($data.catalog | Where-Object id -eq 'Process Creation').guid
    $termination=($data.catalog | Where-Object id -eq 'Process Termination').guid
    $fileSystem=($data.catalog | Where-Object id -eq 'File System').guid
    function Plan { Get-WelaAuditProfilePlan -Profile custom-example -Role Client -Build 26100 -Path $script:file -CustomFile -Current $script:state }
    $script:state=$script:zero.Clone();$script:state[$process]=2
    $plan=Plan
    Assert (($plan.policies | Where-Object id -eq 'Process Creation').targetMask -eq 3) 'Minimum preserves an existing Failure flag.'
    Assert (($plan.policies | Where-Object id -eq 'File System').action -eq 'Optional (not selected)') 'Unselected optional policy is preserved.'
    Assert (($plan.policies | Where-Object id -eq 'Detailed File Share').action -eq 'Preserve') 'Not configured is never disabled.'
    Assert (($plan.policies | Where-Object id -eq 'Kerberos Authentication Service').mode -eq 'not-applicable') 'Canonical DC applicability cannot be expanded by client source.'
    $optional=Get-WelaAuditProfilePlan -Profile custom-example -Role Client -Build 26100 -Path $script:file -CustomFile -Current $script:state -IncludeOptional
    Assert (($optional.policies | Where-Object id -eq 'File System').targetMask -eq 3) 'Explicit IncludeOptional selects the exact object-audit mask, retaining its SACL prerequisite.'
    $override=Copy-Fixture $sample
    $override.profiles[0].roleOverrides | Add-Member MemberServer ([pscustomobject]@{'Process Creation'=[pscustomobject]@{mode='exact';mask=2}})
    Save $override
    $member=Get-WelaAuditProfilePlan -Profile custom-example -Role MemberServer -Build 20348 -Path $script:file -CustomFile -Current $script:state
    Assert (($member.policies | Where-Object id -eq 'Process Creation').requiredMask -eq 2 -and (Plan | Select-Object -ExpandProperty policies | Where-Object id -eq 'Process Creation').requiredMask -eq 1) 'Role override changes only its selected role.'
    $reference=Copy-Fixture $sample; $reference.profiles[0] | Add-Member referenceOnly $true; Save $reference
    $referencePlan=Plan
    Throws {Assert-WelaAuditProfileTarget -Plan $referencePlan -Context ([pscustomobject]@{Role='Client';Build=26100}) -Current $script:state} 'reference'
    Save
    Bad {param($x) $x.schemaVersion='1'} 'schema'
    Bad {param($x) $x | Add-Member command 'whoami'} 'Unknown'
    Bad {param($x) $x.catalog[0].guid='0CCE922E-69AE-11D9-BED3-505054503030'} 'mismatch'
    Bad {param($x) $x.catalog[0].id='process creation'} 'mismatch'
    Bad {param($x) $x.catalog[0].category='Other'} 'mismatch'
    Bad {param($x) $x.catalog[0] | Add-Member prerequisites ''} 'Unknown'
    Bad {param($x) $x.catalog+=@($x.catalog[0])} 'Duplicate'
    Bad {param($x) $x.profiles+=@($x.profiles[0])} 'Duplicate'
    Bad {param($x) $x.profiles[0].id='wela-2.2.0'} 'built-in'
    Bad {param($x) $x.profiles[0].sourceIds=@('missing')} 'Unknown'
    Bad {param($x) $x.sources.organization.version=$null} 'text'
    Bad {param($x) $x.sources.organization.url='file:///tmp/script.ps1'} 'HTTPS'
    Bad {param($x) $x.profiles[0].appliesTo[0].minBuild='26100'} 'integers'
    Bad {param($x) $x.profiles[0].appliesTo[0].maxBuild=1} 'Reversed'
    Bad {param($x) $x.profiles[0].appliesTo[0].roles=@('Client','Client')} 'duplicate'
    Bad {param($x) $x.profiles[0].controls.'Process Creation'.mask='1'} 'integer'
    Bad {param($x) $x.profiles[0].controls.'Process Creation'.mask=$true} 'integer'
    Bad {param($x) $x.profiles[0].controls.'Process Creation'.mask=4} 'integer'
    Bad {param($x) $x.profiles[0].controls.'Process Creation'.mode='enable'} 'mode'
    Bad {param($x) $x.profiles[0].controls.'Detailed File Share' | Add-Member mask 0} 'must not'
    Bad {param($x) $x.profiles[0].controls | Add-Member 'RPC Events' ([pscustomobject]@{mode='exact';mask=3})} 'Unknown'
    Bad {param($x) $x.profiles[0].controls.'Process Creation' | Add-Member script 'Write-Host bad'} 'Unknown'
    Bad {param($x) $x.profiles[0] | Add-Member referenceOnly 'false'} 'boolean'
    Save
    $text=Get-Content -LiteralPath $script:file -Raw
    foreach ($badText in @($text.Replace('"mask": 1','"mask": 1, "MASK": 2'),$text.Replace('"mask": 1','"mask": 1, "m\u0061sk": 2'),$text.Replace('"schemaVersion": 1','"schemaVersion": 1, // comment'),$text.Replace('"mask": 1','"mask": 1,'))) {
        $badText | Set-Content -LiteralPath $script:file -Encoding UTF8
        Throws {Import-WelaCustomAuditProfiles $script:file} 'Duplicate|strict JSON'
    }
    foreach ($badText in @($text.Replace('"schemaVersion"',"'schemaVersion'"),$text.Replace('"schemaVersion"','schemaVersion'),$text.Replace('"mask": 1',"`"mask`": 1, 'mask': 3"),$text.Replace('"mask": 1','"mask": 01'),$text.Replace('"mask": 1','"mask": +1'))) {
        $badText | Set-Content -LiteralPath $script:file -Encoding UTF8
        Throws {Import-WelaCustomAuditProfiles $script:file} 'strict JSON'
    }
    $literal=Copy-Fixture $sample; $literal.profiles[0].note='$(throw "Never execute source data")'; Save $literal
    Assert ((Import-WelaCustomAuditProfiles $script:file).profiles[0].note -ceq $literal.profiles[0].note) 'Executable-looking text stays literal inert metadata.'
    Save; $source=(Import-WelaCustomAuditProfiles $script:file).customSource
    Add-Content -LiteralPath $script:file -Value ' '
    Throws {Assert-WelaCustomProfileSource $source} 'changed'
    Save; $source=(Import-WelaCustomAuditProfiles $script:file).customSource; $source.CanonicalSha256='0'*64
    Throws {Assert-WelaCustomProfileSource $source} 'changed'
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'WELA.ps1'),[ref]$tokens,[ref]$errors)
    Assert ($errors.Count -eq 0) 'Public CLI parses.'
    foreach ($name in @('Get-WelaSelectedContext','Show-WelaAuditProfilePrerequisites','Invoke-WelaProfileCommand')) {
        $node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
        . ([scriptblock]::Create($node.Extent.Text))
    }
    $script:nativeReads=0; $script:writes=0; $script:hostBuild=26100; $script:precedence=1; $script:mutateAtPrompt=$false
    function TestWindows {$true}
    function TestAdministrator {$true}
    function Get-WelaHostContext {$script:nativeReads++;[pscustomobject]@{Role='Client';Build=$script:hostBuild}}
    function Get-WelaEffectiveAuditPolicy {$script:nativeReads++;$script:state.Clone()}
    function Get-WelaNativeAuditPolicy {param($Guid) $script:state[$Guid]}
    function Get-WelaAuditPrecedenceSource {[pscustomobject]@{Description='mock';ConflictsWithRequiredValue=$false}}
    function Get-WelaRegistryState {param($Path,$Name) [pscustomobject]@{ValueExists=$true;KeyExists=$true;Value=$script:precedence;Type='DWord'}}
    function New-WelaRegistryKey {param($Path)}
    function Set-ItemProperty {param($LiteralPath,$Name,$Value,$Type,$ErrorAction) $script:writes++;$script:precedence=$Value}
    function Get-WelaTargetedSaclPlan {param($AuditPlan,$Mode,$Live) [pscustomobject]@{Mode='Skip';Targets=@();TelemetryGap='SACL proof absent'}}
    function Invoke-WelaNative {
        param($FilePath,$Arguments)
        if ($FilePath -ne 'auditpol.exe') {throw 'Unexpected native command'}
        $guid=($Arguments | Where-Object {$_ -like '/subcategory:*'}) -replace '^/subcategory:\{','' -replace '\}$',''
        if ($Arguments -contains '/success:enable') {$script:state[$guid]=$script:state[$guid] -bor 1}
        if ($Arguments -contains '/failure:enable') {$script:state[$guid]=$script:state[$guid] -bor 2}
        if ($Arguments -contains '/success:disable') {$script:state[$guid]=$script:state[$guid] -band 2}
        if ($Arguments -contains '/failure:disable') {$script:state[$guid]=$script:state[$guid] -band 1}
        $script:writes++
    }
    function Read-Host {param($Prompt) if ($script:mutateAtPrompt) { Add-Content -LiteralPath $script:file -Value ' ';$script:mutateAtPrompt=$false };'y'}
    $script:ProfileFile=$script:file;$script:Profile='custom-example';$script:Role='Client';$script:Build=26100
    $script:Baseline=$null;$script:IncludeOptional=$false;$script:SaclMode='Skip';$script:Auto=$true;$script:DryRun=$true
    $script:PlanPath=$null;$script:ResultsPath=$null;$script:BackupPath=$null
    Save; $script:state=$script:zero.Clone()
    $script:ResultsPath=Join-Path $temp 'readonly.json'
    Invoke-WelaProfileCommand audit-settings | Out-Null
    $readonly=Get-Content -LiteralPath $script:ResultsPath -Raw | ConvertFrom-Json
    Assert ($readonly.policies.Count -eq 59 -and $readonly.CustomProfileSource.Sha256) 'Custom read-only audit exports effective masks and selected source via ResultsPath.'
    $script:ResultsPath=$null
    Invoke-WelaProfileCommand configure | Out-Null
    Assert ($script:writes -eq 0) 'Public custom configure DryRun performs no registry/audit mutation.'
    Bad {param($x) $x.catalog[0].guid='bad'} 'mismatch'
    $script:nativeReads=0
    Throws {Invoke-WelaProfileCommand configure} 'mismatch'
    Assert ($script:nativeReads -eq 0 -and $script:writes -eq 0) 'Malformed custom file is refused before host reads or configuration.'
    Save;$script:Profile='wela-2.2.0'
    Throws {Invoke-WelaProfileCommand configure} 'fallback'
    Assert ($script:nativeReads -eq 0) 'Selected built-in profile cannot silently override file selection.'
    $script:Profile='custom-example';$script:Build=17763
    Throws {Invoke-WelaProfileCommand configure} 'does not support'
    Assert ($script:nativeReads -eq 0) 'Explicit unsupported target is refused before host reads.'
    $script:Build=26100;$script:ResultsPath=Join-Path $temp './profile.json'
    Throws {Invoke-WelaProfileCommand configure} 'paths must differ'
    $script:ResultsPath=$null
    # Existing hard links are distinct names for the same source bytes. Neither
    # output aliases nor input aliases may evade source protection before reads.
    $alias=Join-Path $temp 'source-alias.json'
    $null=New-Item -ItemType HardLink -Path $alias -Value $script:file
    $sourceHash=(Get-FileHash $script:file).Hash;$script:nativeReads=0
    $script:ResultsPath=$alias
    Throws {Invoke-WelaProfileCommand plan} 'output already exists'
    $script:ProfileFile=$alias;$script:ResultsPath=$script:file
    Throws {Invoke-WelaProfileCommand plan} 'output already exists'
    Assert ($script:nativeReads -eq 0 -and (Get-FileHash $script:file).Hash -ceq $sourceHash) 'Alias collisions preserve source bytes and fail before host reads.'
    $script:ProfileFile=$script:file;$script:ResultsPath=$null
    Remove-Item -LiteralPath $alias
    $script:PlanPath=Join-Path $temp 'same-output.json';$script:ResultsPath=$script:PlanPath
    Throws {Invoke-WelaProfileCommand plan} 'distinct new report files'
    $script:PlanPath=$null;$script:ResultsPath=$null
    $reportTarget=Join-Path $temp 'protected-report.json'
    Write-WelaCustomProfileReport ([pscustomobject]@{status='original'}) $reportTarget
    Throws {Write-WelaCustomProfileReport ([pscustomobject]@{status='replacement'}) $reportTarget} 'output already exists'
    Assert ((Get-Content $reportTarget -Raw|ConvertFrom-Json).status -eq 'original') 'Final report writer preserves existing artifacts instead of overwriting aliases.'
    $script:state=$script:zero.Clone();$script:state[$process]=2;$script:state[$termination]=3;$script:precedence=0
    $script:BackupPath=Join-Path $temp 'applied';$script:ResultsPath=Join-Path $temp 'applied.json';$script:DryRun=$false
    Invoke-WelaProfileCommand configure | Out-Null
    $report=Get-Content -LiteralPath $script:ResultsPath -Raw | ConvertFrom-Json
    Assert ($report.ExitCode -eq 0 -and $script:state[$process] -eq 3 -and $script:state[$termination] -eq 1 -and $script:state[$fileSystem] -eq 0 -and $script:precedence -eq 1) 'Shared engine preserves minimum bits, applies exact bits and precedence, and omits optional SACL policy.'
    Assert ($report.CustomProfileSource.Sha256 -ceq $report.SchemaSha256) 'Applied result retains selected input provenance.'
    $entries=@(Get-Content -LiteralPath (Join-Path $script:BackupPath 'before.jsonl') | ForEach-Object {$_ | ConvertFrom-Json})
    Assert ($entries.Count -eq 3 -and @($entries | Where-Object {$_.CustomProfileSource.Sha256 -cne $report.SchemaSha256}).Count -eq 0) 'Every prerequisite/audit journal entry records the selected file hash.'
    $script:BackupPath=Join-Path $temp 'prompt-race';$script:ResultsPath=Join-Path $temp 'race.json';$script:Auto=$false;$script:mutateAtPrompt=$true
    $script:state=$script:zero.Clone();$script:precedence=0;$script:writes=0
    Throws {Invoke-WelaProfileCommand configure} 'failed'
    Assert ($script:writes -eq 0) 'File replacement during confirmation refuses precedence and dependent writes.'
    Save;$plan=Plan;$ctx=New-WelaConfigurationContext -DryRun
    $script:hostBuild=26200
    Throws {Set-WelaProfileAuditControls -Context $ctx -Plan $plan} 'target role/build changed'
    $script:hostBuild=26100;$script:state[$process]=1;$script:state[$termination]=1;$script:precedence=1;$plan=Plan
    $ctx=New-WelaConfigurationContext -DryRun
    Set-WelaProfileAuditControls $ctx $plan
    Add-Content -LiteralPath $script:file -Value ' '
    $final=Complete-WelaConfiguration -Context $ctx -Plan $plan
    Assert ($final.ExitCode -eq 1 -and $final.Failed -ge 1) 'Final verification detects input drift after initially compliant controls.'
    Save
    $exe=(Get-Process -Id $PID).Path
    foreach ($arguments in @(@('configure','-ProfileFile',$script:file),@('configure-sacl','-ProfileFile',$script:file),@('configure','-Profile','custom-example','-ProfileFile',$script:file,'-OutgoingNtlmMode','Deny'))) {
        $ErrorActionPreference='Continue';try {$output=& $exe -NoProfile -File (Join-Path $root 'WELA.ps1') @arguments 2>&1;$code=$LASTEXITCODE}finally{$ErrorActionPreference='Stop'}
        Assert ($code -ne 0 -and ($output -join "`n") -match 'ProfileFile|Unsupported option') 'Wrong/missing custom profile options stop public dispatch.'
    }
    Write-Host "PASS: $script:count custom-profile assertions; all native mutations were mocked."
} finally {Remove-Item -LiteralPath $temp -Recurse -Force}
$global:LASTEXITCODE=0
