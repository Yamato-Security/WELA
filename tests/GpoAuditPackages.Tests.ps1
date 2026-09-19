# Offline fixtures only; no LGPO, auditpol mutation, GPMC or domain operations.
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/AuditProfiles.psm1') -Force
. (Join-Path $repo 'scripts/GpoAuditPackages.ps1')
$script:checks=0
function Assert($Value,[string]$Message){if(-not $Value){throw "FAIL: $Message"};$script:checks++}
function Reject([scriptblock]$Code,[string]$Pattern){$message='';try{& $Code|Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern, got $message"}
function New-GPO {throw 'Forbidden domain mutation'}
function Import-GPO {throw 'Forbidden domain mutation'}
function Set-WelaEffectiveAuditPolicy {throw 'Forbidden policy mutation'}
function Invoke-WelaNative {throw 'Forbidden native process'}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-gpo-tests-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
function FreshPath {Join-Path $temp ([guid]::NewGuid().ToString('N'))}
function Clone($Value){ConvertTo-Json -InputObject $Value -Depth 18|ConvertFrom-Json}
function SaveManifest($Path,$Manifest){$Manifest|ConvertTo-Json -Depth 18|Set-Content -LiteralPath (Join-Path $Path 'manifest.json') -Encoding UTF8}
try {
 $plan=Get-WelaGpoPackagePlan -Profile wela-2.2.0 -Role Client -Build 26100
 Assert ($plan.Controls.Count -eq 59 -and $plan.Blockers.Count -eq 0) 'Shared catalog produces the full review, including omitted controls'
 Assert ($plan.ContextBasis -match 'Operator-declared' -and $plan.SigmaEvtxCredit -eq 0 -and -not $plan.ImportableGpoBackup -and -not $plan.DeploymentVerified) 'Declared deployment context is never host, GPO or detection evidence'
 Assert ($plan.ProfileSchemaSha256 -match '^[a-f0-9]{64}$' -and $plan.Sources.Count -gt 0 -and $plan.UnsupportedControls.Count -gt 0) 'Source fingerprint, provenance and unsupported scopes stay visible'
 Assert (@($plan.Controls|Where-Object {$_.Name -eq 'Directory Service Changes' -and $_.Disposition -eq 'Omitted'}).Count -eq 1) 'DC-only directory auditing is omitted on a client'
 $dc=Get-WelaGpoPackagePlan -Profile wela-2.2.0 -Role DomainController -Build 20348
 Assert (@($dc.Controls|Where-Object {$_.Name -eq 'Directory Service Changes' -and $_.Disposition -eq 'Exported'}).Count -eq 1) 'The same source respects explicit DC scope'
 $ca=Get-WelaGpoPackagePlan -Profile wela-2.2.0 -Role ADCS -Build 20348
 Assert (@($ca.Controls|Where-Object {$_.Name -eq 'Certification Services' -and $_.Disposition -eq 'Exported'}).Count -eq 1) 'AD CS target audit policy is retained without claiming AuditFilter or SACL configuration'
 Reject {Get-WelaGpoPackagePlan -Profile cis-server2022-v4-l1 -Role Client -Build 26100} 'does not support'
 Reject {Get-WelaGpoPackagePlan -Profile unknown -Role Client -Build 26100} 'Unknown audit profile'
 $reference=Get-WelaGpoPackagePlan -Profile windows-defaults-reviewed-2026-09 -Role Client -Build 26100
 Assert ($reference.Blockers -match 'Reference-only') 'Documentary defaults cannot become deployment policy'
 $minimum=Get-WelaGpoPackagePlan -Profile microsoft-wef-reviewed-2026-09 -Role MemberServer -Build 20348
 Assert ($minimum.Blockers.Count -gt 0 -and @($minimum.Controls|Where-Object {$_.SourceMode -eq 'minimum' -and $_.RequiredMask -in @(1,2) -and $_.Disposition -eq 'Exported'}).Count -eq 0) 'Minimum masks cannot silently become restrictive exact masks'
 $both=Get-WelaGpoPackagePlan -Profile microsoft-wef-reviewed-2026-09 -Role MemberServer -Build 20348 -MinimumMode PromoteToBoth
 Assert ($both.Blockers.Count -eq 0 -and @($both.Controls|Where-Object {$_.SourceMode -eq 'minimum' -and $_.RequiredMask -in @(1,2) -and $_.ExportMask -eq 3 -and $_.Reason -match 'expansion'}).Count -gt 0) 'Explicit promotion records each expanded exact Both mask'
 # Exercise all semantic states independently of which happen to exist in today's sources.
 $raw=Get-WelaAuditProfilePlan -Profile wela-2.2.0 -Role Client -Build 26100
 $fixture=Clone $raw;$base=$fixture.policies[0];$fixture.policies=@()
 foreach($setting in @(@('exact',1),@('exact',2),@('exact',3),@('minimum',0),@('minimum',1),@('minimum',2),@('minimum',3),@('not-configured',$null),@('unchanged',$null),@('not-applicable',$null),@('optional',3))) {
  $row=Clone $base;$row.mode=$setting[0];$row.requiredMask=$setting[1];$fixture.policies+=@($row)
 }
 $translated=ConvertTo-WelaGpoPackagePlan $fixture -MinimumMode PromoteToBoth
 Assert (($translated.Controls[0..2].ExportMask -join ',') -eq '1,2,3') 'Exact positive masks preserve their precise meaning'
 Assert ($translated.Controls[3].Disposition -eq 'Omitted' -and ($translated.Controls[4..6].ExportMask -join ',') -eq '3,3,3') 'Minimum zero omits and positive minima resolve only to Both'
 Assert (@($translated.Controls[7..10]|Where-Object Disposition -ne 'Omitted').Count -eq 0) 'Not Configured, unchanged, inapplicable and unselected optional rows remain omitted'
 $fixture.includeOptional=$true
 Assert ((ConvertTo-WelaGpoPackagePlan $fixture -MinimumMode PromoteToBoth).Controls[10].ExportMask -eq 3) 'Selected optional positive mask becomes exact'
 $fixture.policies[0].requiredMask=0
 $zero=ConvertTo-WelaGpoPackagePlan $fixture -MinimumMode PromoteToBoth
 Assert ($zero.Controls[0].Disposition -eq 'Blocked' -and $zero.Controls[0].Reason -match 'value 4') 'No Auditing versus unchanged CSV conflict is explicit and blocks export'
 $zeroPath=FreshPath;Reject {Export-WelaGpoPackage $zero $zeroPath} 'blocked';Assert (-not(Test-Path $zeroPath)) 'Blocked plans create no output'
 $fixture.policies=@($fixture.policies[7]);$empty=ConvertTo-WelaGpoPackagePlan $fixture
 Assert ($empty.Blockers -match 'No applicable') 'An omission-only profile cannot silently export precedence alone'
 $plain=Get-WelaGpoComponentContent $plan
 $csv=@($plain['audit.csv'].Text|ConvertFrom-Csv)
 Assert ($csv.Count -eq @($plan.Controls|Where-Object Disposition -eq 'Exported').Count) 'CSV contains exactly the selected rows'
 Assert (@($csv|Where-Object {$_.'Policy Target' -cne 'System' -or $_.'Machine Name' -ne '' -or $_.'Exclusion Setting' -ne '' -or $_.'Setting Value' -notin @('1','2','3')}).Count -eq 0) 'CSV has no per-user/exclusion/audit-option or zero rows'
 Assert ($csv[0].PSObject.Properties.Name.Count -eq 7 -and $plain['audit.csv'].Text -notmatch '(?<!\r)\n') 'Documented CSV header has seven columns and CRLF endings'
 $rpc=@($csv|Where-Object Subcategory -eq 'RPC Events')
 $token=@($plan.Controls|Where-Object Name -eq 'Token Right Adjusted Events')
 Assert ($rpc.Count -eq 1 -and $rpc[0].'Subcategory GUID' -eq '{0CCE922E-69AE-11D9-BED3-505054503030}' -and $token[0].Guid -eq '0CCE924A-69AE-11D9-BED3-505054503030' -and $token[0].Disposition -eq 'Omitted') 'RPC exports independently while unchanged token auditing retains its canonical review identity'
 $regLines=@($plain['GptTmpl.inf'].Text -split "`r`n"|Where-Object {$_ -like 'MACHINE*'})
 Assert ($regLines.Count -eq 1 -and $regLines[0] -ceq 'MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy=4,1') 'Template contains only the typed precedence value'
 $infBytes=Get-WelaGpoContentBytes $plain['GptTmpl.inf'];$csvBytes=Get-WelaGpoContentBytes $plain['audit.csv']
 Assert ($infBytes[0] -eq 255 -and $infBytes[1] -eq 254 -and $csvBytes[0] -eq [byte][char]'M') 'Security template has UTF-16LE BOM; audit CSV is UTF-8 without BOM'
 $path=FreshPath;$dry=Export-WelaGpoPackage $plan $path -DryRun
 Assert ($dry.DryRun -and -not(Test-Path $path) -and @(Get-ChildItem $temp -Force).Count -eq 0) 'Dry-run creates neither output nor staging directory'
 $result=Export-WelaGpoPackage $plan $path
 Assert ($result.ExitCode -eq 0 -and $result.Action -eq 'Export' -and -not $result.DeploymentVerified -and @(Get-ChildItem $path -Force).Count -eq 5) 'Export publishes exactly the verified component files without deployment claims'
 $verified=Invoke-WelaGpoPackageCommand -Action Verify -Path $path
 Assert ($verified.ExitCode -eq 0 -and $verified.Action -eq 'Verify' -and $verified.Plan.Profile -eq $plan.Profile) 'Read-only verification reconstructs source intent'
 Reject {Export-WelaGpoPackage $plan $path} 'fresh output'
 $filePath=FreshPath;'keep'|Set-Content $filePath;Reject {Export-WelaGpoPackage $plan $filePath} 'fresh output';Assert ((Get-Content $filePath) -eq 'keep') 'Existing files are not overwritten'
 Reject {Export-WelaGpoPackage $plan (Join-Path (FreshPath) 'missing-parent')} 'parent directory'
 foreach($case in @('payload','updated-hash','intent','source-hash','extra-file','extra-manifest','extra-filemetadata','duplicate-file','missing-file','encoding','guide')) {
  $altered=FreshPath;$null=Copy-Item -LiteralPath $path -Destination $altered -Recurse
  $manifest=Get-Content (Join-Path $altered 'manifest.json') -Raw|ConvertFrom-Json
  switch($case) {
   'payload' {Add-Content (Join-Path $altered 'audit.csv') 'unreviewed'}
   'updated-hash' {Add-Content (Join-Path $altered 'audit.csv') 'unreviewed';$bytes=[IO.File]::ReadAllBytes((Join-Path $altered 'audit.csv'));$manifest.Files[0].Length=$bytes.Length;$manifest.Files[0].Sha256=Get-WelaGpoBytesHash $bytes}
   'intent' {$manifest.Plan.Controls[0].ExportMask=2}
   'source-hash' {$manifest.Plan.ProfileSchemaSha256='0'*64}
   'extra-file' {'unreviewed'|Set-Content (Join-Path $altered 'Backup.xml')}
   'extra-manifest' {$manifest|Add-Member NoteProperty ImportableGpoBackup $true}
   'extra-filemetadata' {$manifest.Files[0]|Add-Member NoteProperty Executable $true}
   'duplicate-file' {$manifest.Files[1]=$manifest.Files[0]}
   'missing-file' {Remove-Item (Join-Path $altered 'audit.csv')}
   'encoding' {$manifest.Files[0].Encoding='utf-16'}
   'guide' {Add-Content (Join-Path $altered 'deployment.md') 'unreviewed deployment'}
  }
  SaveManifest $altered $manifest
  Reject {Test-WelaGpoPackage $altered} 'differs|match|exactly|Unexpected|duplicate'
 }
 $link=FreshPath
 $null=New-Item -ItemType SymbolicLink -Path $link -Target $path
 Reject {Test-WelaGpoPackage $link} 'Reparse'
 Reject {Export-WelaGpoPackage $plan (Join-Path $link 'child')} 'Reparse'
 $memberLink=FreshPath;$null=Copy-Item $path $memberLink -Recurse
 Remove-Item (Join-Path $memberLink 'audit.csv');$null=New-Item -ItemType SymbolicLink -Path (Join-Path $memberLink 'audit.csv') -Target (Join-Path $path 'audit.csv')
 Reject {Test-WelaGpoPackage $memberLink} 'reparse'
 # A raced destination must survive; the staged payload must never merge into it.
 $racedPath=FreshPath;$originalVerifier=${function:Test-WelaGpoPackage}
 & {
  function Test-WelaGpoPackage {param($Path) if($Path -like '*stage*' -and -not(Test-Path $racedPath)){'concurrent owner'|Set-Content $racedPath};& $originalVerifier $Path}
  Reject {Export-WelaGpoPackage $plan $racedPath} 'did not complete'
 }
 Assert ((Get-Content $racedPath) -eq 'concurrent owner') 'Atomic publication preserves a concurrent destination'
 & {
  $script:hashReads=0
  function Get-FileHash {param($LiteralPath,$Algorithm,$ErrorAction) $script:hashReads++;if($script:hashReads -ge 2){[pscustomobject]@{Hash=('0'*64)}}else{Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $LiteralPath -Algorithm $Algorithm}}
  Reject {Get-WelaGpoPackagePlan -Profile wela-2.2.0 -Role Client -Build 26100} 'changed during planning'
 }
 Reject {Invoke-WelaGpoPackageCommand} 'explicit'
 Reject {Invoke-WelaGpoPackageCommand -Action Verify -Path $path -Profile wela-2.2.0} 'overrides'
 Reject {Invoke-WelaGpoPackageCommand -Action Verify -Path $path -DryRun} 'DryRun'
 Reject {Invoke-WelaGpoPackageCommand -Profile wela-2.2.0 -Role Client -Build 26100 -Path $path} 'only with Export'
 # The actual CLI's early guard runs before an unrelated configuration profile dispatch.
 $errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'WELA.ps1'),[ref]$null,[ref]$errors)
 Assert ($errors.Count -eq 0) 'Public CLI parses'
 $nodes=@($ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.IfStatementAst] -and ($_.Extent.Text -match 'GPO package options require' -or $_.Extent.Text -match 'Invoke-WelaProfileCommand -Command')})
 Assert ($nodes.Count -eq 2) 'Both dedicated guard and existing profile dispatcher remain present'
 $dispatch=[scriptblock]::Create('param($Cmd,$Profile,$GpoAction,$GpoProfile,$GpoOutputPath,$GpoMinimumMode)'+[Environment]::NewLine+(($nodes|ForEach-Object {$_.Extent.Text})-join [Environment]::NewLine))
 function Invoke-WelaProfileCommand {throw 'UNSAFE unrelated dispatcher'}
 foreach($option in @('GpoAction','GpoProfile','GpoOutputPath','GpoMinimumMode')) {$arguments=@{Cmd='configure';Profile='wela'};$arguments[$option]='value';Reject {& $dispatch @arguments} 'GPO package options require'}
 Write-Host "PASS: $script:checks GPO component assertions. No native policy or domain changes."
} finally {Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}
