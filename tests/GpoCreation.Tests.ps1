# Synthetic orchestration fixtures. They never create/import a real domain GPO.
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/AuditProfiles.psm1') -Force
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/GpoAuditPackages.ps1')
. (Join-Path $repo 'scripts/EvtxRecovery.ps1')
. (Join-Path $repo 'scripts/GpoCreation.ps1')
$script:checks=0
function Assert($Value,[string]$Message){if(-not $Value){throw "FAIL: $Message"};$script:checks++}
function Reject([scriptblock]$Code,[string]$Pattern){$message='';try{& $Code|Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern, got $message"}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-gpo-create-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $temp
function SaveText($Path,[string]$Text){[IO.File]::WriteAllText($Path,$Text,[Text.UTF8Encoding]::new($false))}
function FreshPath {Join-Path $temp ([guid]::NewGuid().ToString('N'))}
$script:backupId='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';$script:sourceId='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';$script:createdId='cccccccc-cccc-cccc-cccc-cccccccccccc'
$script:plan=Get-WelaGpoPackagePlan wela-2.2.0 Client 26100
function New-Fixture {
    $root=FreshPath;$null=New-Item -ItemType Directory $root
    $package=Join-Path $root 'package';$null=Export-WelaGpoPackage $script:plan $package
    $backupRoot=Join-Path $root 'backups';$backup=Join-Path $backupRoot ('{'+$script:backupId+'}')
    $audit=Join-Path $backup 'DomainSysvol/GPO/Machine/microsoft/windows nt/Audit';$inf=Join-Path $backup 'DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit'
    $null=New-Item -ItemType Directory $audit -Force;$null=New-Item -ItemType Directory $inf -Force
    Copy-Item (Join-Path $package 'audit.csv') (Join-Path $audit 'audit.csv');Copy-Item (Join-Path $package 'GptTmpl.inf') (Join-Path $inf 'GptTmpl.inf')
    $settings='';foreach($row in $script:plan.Controls|Where-Object Disposition -eq Exported){$settings+='<a:AuditSetting><a:PolicyTarget>System</a:PolicyTarget><a:SubcategoryName>Localized display</a:SubcategoryName><a:SubcategoryGuid>{'+$row.Guid+'}</a:SubcategoryGuid><a:SettingValue>'+$row.ExportMask+'</a:SettingValue></a:AuditSetting>'}
    $report='<GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings" xmlns:t="http://www.microsoft.com/GroupPolicy/Types" xmlns:a="http://www.microsoft.com/GroupPolicy/Settings/Auditing" xmlns:s="http://www.microsoft.com/GroupPolicy/Settings/Security"><Identifier><t:Identifier>{'+$script:sourceId+'}</t:Identifier><t:Domain>example.test</t:Domain></Identifier><Name>Audit Source</Name><Computer><VersionDirectory>1</VersionDirectory><VersionSysvol>1</VersionSysvol><Enabled>false</Enabled><ExtensionData><Extension>'+$settings+'</Extension><Name>Localized auditing</Name></ExtensionData><ExtensionData><Extension><s:SecurityOptions><s:KeyName>MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy</s:KeyName><s:SettingNumber>1</s:SettingNumber><s:Display><s:Name>Localized name</s:Name></s:Display></s:SecurityOptions></Extension><Name>Security</Name></ExtensionData></Computer><User><VersionDirectory>0</VersionDirectory><VersionSysvol>0</VersionSysvol><Enabled>false</Enabled></User></GPO>'
    SaveText (Join-Path $backup 'gpreport.xml') $report
    $fs='';foreach($file in @('Audit\audit.csv','SecEdit\GptTmpl.inf')){
        $rel='microsoft\windows nt\'+$file
        $fs+='<FSObjectFile bkp:Path="%GPO_MACH_FSPATH%\'+$rel+'" bkp:SourceExpandedPath="\\dc.example.test\sysvol\example.test\Policies\{'+$script:sourceId+'}\Machine\'+$rel+'" bkp:Location="DomainSysvol\GPO\Machine\'+$rel+'"/>'
    }
    $xml='<GroupPolicyBackupScheme xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations" xmlns:bkp="http://www.microsoft.com/GroupPolicy/GPOOperations" bkp:version="2.0" bkp:type="GroupPolicyBackupTemplate"><GroupPolicyObject><SecurityGroups/><FilePaths/><GroupPolicyCoreSettings><ID>{'+$script:sourceId+'}</ID><Domain>example.test</Domain><SecurityDescriptor>01 00</SecurityDescriptor><DisplayName>Audit Source</DisplayName><Options>3</Options><UserVersionNumber>0</UserVersionNumber><MachineVersionNumber>65537</MachineVersionNumber><MachineExtensionGuids>[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}][{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]</MachineExtensionGuids><UserExtensionGuids/><WMIFilter/></GroupPolicyCoreSettings><GroupPolicyExtension bkp:ID="{F15C46CD-82A0-4C2D-A210-5D0D3182A418}" bkp:DescName="Unknown Extension">'+$fs+'</GroupPolicyExtension></GroupPolicyObject></GroupPolicyBackupScheme>'
    SaveText (Join-Path $backup 'Backup.xml') $xml
    SaveText (Join-Path $backup 'bkupInfo.xml') ('<BackupInst xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations/Manifest"><ID>{'+$script:backupId+'}</ID><GPOGuid>{'+$script:sourceId+'}</GPOGuid><GPODomain>example.test</GPODomain><GPODisplayName>Audit Source</GPODisplayName></BackupInst>')
    $config=[ordered]@{SchemaVersion=1;PackagePath=$package;BackupRoot=$backupRoot;BackupId=$script:backupId;Domain='example.test';DomainGuid='dddddddd-dddd-dddd-dddd-dddddddddddd';Dc='dc.example.test';Name='Reviewed Audit Candidate';ReviewedSha256=''}
    $configPath=Join-Path $root 'create.json';SaveText $configPath ($config|ConvertTo-Json)
    [pscustomobject]@{Root=$root;Package=$package;Backup=$backup;Config=$config;ConfigPath=$configPath;Report=$report}
}
# The only native backup adapter is mocked. Production XML/payload/package/inventory validation runs.
function Get-WelaGpoNativeBackup {param($Root,$Id) [pscustomobject]@{Xml=[IO.File]::ReadAllText((Join-Path (Join-Path $Root ('{'+$Id+'}')) 'gpreport.xml'));Backup='FixtureNativeBackup';Id=$Id}}
$script:nativeBackupAdapter=${function:Get-WelaGpoNativeBackup}
function Ready($Fixture) {$r=Invoke-WelaGpoCreateCommand -ConfigPath $Fixture.ConfigPath;$Fixture.Config.ReviewedSha256=$r.ReviewedSha256;SaveText $Fixture.ConfigPath ($Fixture.Config|ConvertTo-Json);$r}
function ResetNative {
    $script:created=0;$script:disabled=0;$script:imported=0;$script:targetReads=0;$script:sessionReads=0;$script:marker='';$script:fault='';$script:exists=$false;$script:operator='S-1-5-21-1-2-3-1001'
}
function Open-WelaGpoCreationSession {param($Config) $script:sessionReads++;if($script:fault -eq 'domain' -or ($script:fault -eq 'domain-race' -and $script:sessionReads -ge 3)){throw 'Actual domain GUID changed'};[pscustomobject]@{Identity=$script:operator;DomainGuid=$Config.DomainGuid;Dc=$Config.Dc}}
function Close-WelaGpoCreationSession {param($Session)}
function Get-WelaGpoNameMatches {param($Session,$Name) if($script:exists -or $script:created){[pscustomobject]@{Name=$Name}}}
function New-WelaGpoNativeTarget {param($Session,$Config,$Marker) $script:created++;$script:marker=$Marker;$script:createdId}
function Disable-WelaGpoNativeTarget {param($Session,$Config,$Id,$Marker) Assert ($Id -eq $script:createdId -and $Marker -ceq $script:marker) 'Disable only returned GUID and ownership marker';$script:disabled++}
function Import-WelaGpoNativeTarget {param($Session,$Id,$Backup) Assert ($Id -eq $script:createdId -and $script:disabled -eq 1 -and $Backup -eq 'FixtureNativeBackup') 'Import only own disabled GUID and validated backup';$script:imported++;if($script:fault -eq 'native-status'){throw 'Native GPMC OverallStatus failed'}}
function Get-WelaGpoNativeTarget {
    param($Session,$Config,$Id,[switch]$Blank,[switch]$AllowEnabled)
    $script:targetReads++
    if(($script:fault -eq 'target-race' -and $Blank -and $script:targetReads -eq 2) -or ($script:fault -eq 'linked' -and -not $Blank)){throw 'New GPO links/blank state changed'}
    $key=if($Blank){''}else{Get-WelaGpoExpectedKey $script:plan}
    if($script:fault -eq 'content' -and -not $Blank){$key='wrong'}
    $permission=if($script:fault -eq 'acl' -and -not $Blank){'O:BAD'}else{'O:SYG:SYD:(A;;GA;;;SY)'}
    $version=if($Blank){0}elseif($script:fault -eq 'final-drift' -and $script:targetReads -ge 4){2}else{1}
    [pscustomobject]@{Id=$Id;Name=$Config.Name;Description=$script:marker;Disabled=$true;Links=0;AuditKey=$key;ComputerVersion=$version;UserVersion=0;Permissions=$permission;Usn=([string](10+$version));ObjectGuid='eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee';Xml='<NativeFixture/>';Inventory=@()}
}
try {
    $placeholder='<GroupPolicyExtension bkp:ID="{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" bkp:DescName="Registry"><FSObjectFile bkp:Path="%GPO_FSPATH%\Adm\*.*" bkp:SourceExpandedPath="\\dc.example.test\sysvol\example.test\Policies\{'+$script:sourceId+'}\Adm\*.*"/></GroupPolicyExtension>'
    $placeholderFixture=New-Fixture;$metadataPath=Join-Path $placeholderFixture.Backup 'Backup.xml'
    $metadata=[IO.File]::ReadAllText($metadataPath).Replace('</GroupPolicyObject>',$placeholder+'</GroupPolicyObject>');SaveText $metadataPath $metadata
    Assert ((Invoke-WelaGpoCreateCommand -ConfigPath $placeholderFixture.ConfigPath).Status -eq 'ReviewedInputsOnly') 'An exact absent legacy ADM placeholder from native GPMC is accepted without registry policy'
    foreach($mutation in @('location','callback','registry','adm-file')) {
        SaveText $metadataPath $metadata
        switch($mutation) {
            location {SaveText $metadataPath ($metadata.Replace('bkp:Path="%GPO_FSPATH%', 'bkp:Location="DomainSysvol\GPO\Adm" bkp:Path="%GPO_FSPATH%'))}
            callback {SaveText $metadataPath ($metadata.Replace('bkp:Path="%GPO_FSPATH%', 'bkp:ReEvaluateFunction="Unknown" bkp:Path="%GPO_FSPATH%'))}
            registry {SaveText $metadataPath ($metadata.Replace('%GPO_FSPATH%\Adm\*.*','%GPO_MACH_FSPATH%\registry.pol'))}
            adm-file {$adm=Join-Path $placeholderFixture.Backup 'DomainSysvol/GPO/Adm';$null=New-Item -ItemType Directory $adm;SaveText (Join-Path $adm 'policy.adm') 'unrelated'}
        }
        Reject {Invoke-WelaGpoCreateCommand -ConfigPath $placeholderFixture.ConfigPath} '.'
    }
    $fixture=New-Fixture;$review=Ready $fixture
    Assert ($review.Status -eq 'ReviewedInputsOnly' -and -not $review.DeploymentVerified -and $review.SigmaEvtxCredit -eq 0 -and $review.ReviewedSha256 -match '^[a-f0-9]{64}$') 'Review binds real component generation and all payload bytes without deployment claims'
    Assert ($review.BackupId -ne $review.SourceGpoId) 'Backup-instance identity stays separate from source GPO GUID'
    ResetNative;$planResult=Invoke-WelaGpoCreateCommand -Action Plan -ConfigPath $fixture.ConfigPath
    Assert ($planResult.Status -eq 'PlanValidated' -and -not $script:created) 'Plan reads domain and refuses mutation'
    ResetNative;$output=FreshPath;$dry=Invoke-WelaGpoCreateCommand -Action Create -ConfigPath $fixture.ConfigPath -Auto -DryRun -BackupPath $output
    Assert ($dry.ExitCode -eq 0 -and $dry.Status -eq 'DryRun_NoGpoCreated' -and -not $script:created -and -not (Test-Path $output)) 'Public dry run creates no output or GPO'
    ResetNative;function Read-Host {'n'};$output=FreshPath;$declined=Invoke-WelaGpoCreateCommand -Action Create -ConfigPath $fixture.ConfigPath -BackupPath $output
    Assert ($declined.Status -eq 'Declined_NoGpoCreated' -and -not $script:created -and -not (Test-Path (Join-Path $output 'created-gpo.json'))) 'Decline preserves domain state'
    ResetNative;$output=FreshPath;$success=Invoke-WelaGpoCreateCommand -Action Create -ConfigPath $fixture.ConfigPath -Auto -BackupPath $output
    Assert ($success.ExitCode -eq 0 -and $success.Status -eq 'DisabledUnlinkedCandidateVerified' -and $script:created -eq 1 -and $script:imported -eq 1) 'One public command orchestrates create, disable, exact GUID import and final verification'
    Assert ($success.CreatedGpoId -eq $script:createdId -and -not $success.DeploymentVerified -and $success.SigmaEvtxCredit -eq 0) 'A verified candidate never claims activated policy or detections'
    foreach($name in @('reviewed-plan.json','before.jsonl','creation-intent.json','created-gpo.json','blank-target.json','import-intent.json','result.json')) {Assert (Test-Path (Join-Path $output $name)) "Durable evidence retained: $name"}
    $receipt=Get-Content (Join-Path $output 'created-gpo.json') -Raw|ConvertFrom-Json;Assert ($receipt.Id -eq $script:createdId -and $receipt.Marker -ceq $script:marker) 'Created GUID and marker are recorded before import'
    ResetNative;Reject {Invoke-WelaGpoCreateCommand -Action Create -ConfigPath $fixture.ConfigPath -Auto -BackupPath $output} 'fresh output'
    ResetNative;$script:exists=$true;Reject {Invoke-WelaGpoCreateCommand -Action Plan -ConfigPath $fixture.ConfigPath} 'already exists';Assert (-not $script:created) 'Existing name is never reused'
    ResetNative;$script:fault='domain';Reject {Invoke-WelaGpoCreateCommand -Action Plan -ConfigPath $fixture.ConfigPath} 'domain GUID';Assert (-not $script:created) 'Unknown/wrong domain fails before creation'
    foreach($faultCase in @('domain-race','target-race','native-status','content','acl','linked','final-drift')) {
        ResetNative;$script:fault=$faultCase;$output=FreshPath;$failed=Invoke-WelaGpoCreateCommand -Action Create -ConfigPath $fixture.ConfigPath -Auto -BackupPath $output
        Assert ($failed.ExitCode -eq 1 -and $failed.Status -eq 'Failed_ReviewRetainedReceipts') "$faultCase is an explicit failed candidate, never a successful handoff"
        if($faultCase -in @('domain-race','target-race')) {Assert ($script:imported -eq 0) "$faultCase blocks import"}
        if($script:created){Assert (Test-Path (Join-Path $output 'created-gpo.json')) "$faultCase retains exact created identity"}
    }
    foreach($case in @('extra-file','extra-directory','audit-mask','user-row','security-right','security-type','report-mask','report-enabled','report-unknown','backup-enabled','backup-id','path-traversal','callback','unknown-extension','duplicate-row','xml-dtd','native-report')) {
        $f=New-Fixture;$backupFile=Join-Path $f.Backup 'Backup.xml';$reportFile=Join-Path $f.Backup 'gpreport.xml';$auditFile=Join-Path $f.Backup 'DomainSysvol/GPO/Machine/microsoft/windows nt/Audit/audit.csv';$templateFile=Join-Path $f.Backup 'DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf'
        switch($case) {
            extra-file {SaveText (Join-Path $f.Backup 'evil.ps1') 'unrelated'}
            extra-directory {$null=New-Item -ItemType Directory (Join-Path $f.Backup 'Unknown')}
            audit-mask {SaveText $auditFile ([IO.File]::ReadAllText($auditFile).Replace(',3',',2'))}
            user-row {SaveText $auditFile ([IO.File]::ReadAllText($auditFile).Replace(',System,',',User,'))}
            security-right {Add-Content -LiteralPath $templateFile -Encoding Unicode -Value "`r`n[Privilege Rights]`r`nSeDebugPrivilege=*S-1-1-0"}
            security-type {SaveText $templateFile ([IO.File]::ReadAllText($templateFile).Replace('=4,1','=1,1'))}
            report-mask {SaveText $reportFile ($f.Report.Replace('<a:SettingValue>3','<a:SettingValue>2'))}
            report-enabled {SaveText $reportFile ($f.Report.Replace('<Enabled>false','<Enabled>true'))}
            report-unknown {SaveText $reportFile ($f.Report.Replace('</Computer>','<UnknownSetting>1</UnknownSetting></Computer>'))}
            backup-enabled {SaveText $backupFile ([IO.File]::ReadAllText($backupFile).Replace('<Options>3','<Options>0'))}
            backup-id {SaveText (Join-Path $f.Backup 'bkupInfo.xml') ([IO.File]::ReadAllText((Join-Path $f.Backup 'bkupInfo.xml')).Replace($script:backupId,$script:sourceId))}
            path-traversal {SaveText $backupFile ([IO.File]::ReadAllText($backupFile).Replace('bkp:Path="%GPO_MACH_FSPATH%','bkp:Path="../%GPO_MACH_FSPATH%'))}
            callback {SaveText $backupFile ([IO.File]::ReadAllText($backupFile).Replace('<FSObjectFile ','<FSObjectFile bkp:ReEvaluateFunction="BadCallback" '))}
            unknown-extension {SaveText $backupFile ([IO.File]::ReadAllText($backupFile).Replace('F15C46CD-82A0-4C2D-A210-5D0D3182A418','FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF'))}
            duplicate-row {$lines=[IO.File]::ReadAllLines($auditFile);Add-Content $auditFile $lines[1]}
            xml-dtd {SaveText $reportFile ('<!DOCTYPE GPO [<!ENTITY x SYSTEM "file:///bad">]>'+$f.Report)}
            native-report {function Get-WelaGpoNativeBackup {param($Root,$Id) [pscustomobject]@{Xml=$fixture.Report.Replace('Audit Source','Different Source');Backup='FixtureNativeBackup'}}}
        }
        ResetNative;Reject {Invoke-WelaGpoCreateCommand -ConfigPath $f.ConfigPath} '.';Assert (-not $script:created) "$case is rejected before domain creation"
        ${function:Get-WelaGpoNativeBackup}=$script:nativeBackupAdapter
    }
    $f=New-Fixture;$null=Ready $f;$f.Config.ReviewedSha256='0'*64;SaveText $f.ConfigPath ($f.Config|ConvertTo-Json)
    Reject {Invoke-WelaGpoCreateCommand -Action Plan -ConfigPath $f.ConfigPath} 'ReviewedSha256'
    $f=New-Fixture;$original=$f.Config|ConvertTo-Json -Compress;$duplicate=$original.Replace('"SchemaVersion":1','"SchemaVersion":1,"SchemaVersion":1')
    Assert ($duplicate -cne $original) 'Duplicate-key test actually changes JSON under both PowerShell engines'
    SaveText $f.ConfigPath $duplicate
    Reject {Read-WelaGpoCreateConfig $f.ConfigPath} 'Duplicate'
    foreach($field in @('Domain','Dc')) {$f=New-Fixture;$f.Config[$field]='10.0.0.1';SaveText $f.ConfigPath ($f.Config|ConvertTo-Json);Reject {Read-WelaGpoCreateConfig $f.ConfigPath} 'DNS names'}
    Reject {Assert-WelaGpmResult ([pscustomobject]@{OverallStatus=0})} 'native GPMC result'
    Reject {Invoke-WelaGpoCreateCommand -Action Review -ConfigPath $fixture.ConfigPath -Auto} 'require'
    Reject {Invoke-WelaGpoCreateCommand -Action Create -ConfigPath $fixture.ConfigPath} 'explicit fresh'
    # Durable receipt failure after creation blocks disabling/import; the precreation marker still exists.
    $writer=${function:Write-WelaGpoReceipt}
    function Write-WelaGpoReceipt {param($Root,$Name,$Value) if($Name -eq 'created-gpo.json'){throw 'Receipt disk failure'};& $writer $Root $Name $Value}
    ResetNative;$output=FreshPath;$failed=Invoke-WelaGpoCreateCommand -Action Create -ConfigPath $fixture.ConfigPath -Auto -BackupPath $output
    Assert ($failed.ExitCode -eq 1 -and $script:created -eq 1 -and $script:disabled -eq 0 -and $script:imported -eq 0 -and $failed.CreatedGpoId -eq $script:createdId) 'Postcreation receipt failure leaves an empty GPO and never imports policy'
    ${function:Write-WelaGpoReceipt}=$writer
    # Prompt-time input change is caught after consent and before any native mutation.
    ResetNative;function Read-Host {Add-Content (Join-Path $fixture.Package 'audit.csv') 'drift';'y'};$output=FreshPath
    $failed=Invoke-WelaGpoCreateCommand -Action Create -ConfigPath $fixture.ConfigPath -BackupPath $output
    Assert ($failed.ExitCode -eq 1 -and -not $script:created) 'Changed package after prompt is refused before creation'
    Write-Host "GPO creation fixtures: $script:checks assertions passed (native domain operations mocked)."
} finally {Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}
$global:LASTEXITCODE=0
