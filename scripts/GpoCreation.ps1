# New, disabled, unlinked GPOs only. Never restore, overwrite, link, enable or delete a GPO.
function Read-WelaGpoXml {
    param([string]$Text)
    $settings=New-Object Xml.XmlReaderSettings
    $settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=4194304
    $reader=[Xml.XmlReader]::Create([IO.StringReader]::new($Text),$settings)
    try {$doc=New-Object Xml.XmlDocument;$doc.XmlResolver=$null;$doc.Load($reader);return ,$doc} finally {$reader.Dispose()}
}
function Get-WelaGpoChildren {
    param($Node,[string[]]$Allowed,[string]$Namespace=$Node.NamespaceURI,[string[]]$Repeated=@())
    $seen=@{}
    foreach($child in $Node.ChildNodes) {
        if ($child.NodeType -in @('Whitespace','Comment')) {continue}
        if ($child.NodeType -ne 'Element' -or $child.NamespaceURI -cne $Namespace -or $child.LocalName -cnotin $Allowed -or ($seen.ContainsKey($child.LocalName) -and $child.LocalName -cnotin $Repeated)) {throw "Unexpected/duplicate GPO XML content: $($Node.LocalName)/$($child.LocalName)"}
        $seen[$child.LocalName]=$true
    }
}
function Get-WelaGpoText {
    param($Node,[string]$Name,[string]$Namespace=$Node.NamespaceURI)
    $found=@($Node.ChildNodes|Where-Object {$_.NodeType -eq 'Element' -and $_.LocalName -ceq $Name -and $_.NamespaceURI -ceq $Namespace})
    if($found.Count -ne 1 -or @($found[0].ChildNodes|Where-Object NodeType -eq Element).Count) {throw "Missing/ambiguous scalar GPO XML field: $Name"}
    [string]$found[0].InnerText
}
function Get-WelaGpoGuid {
    param([string]$Value)
    if($Value -notmatch '^\{?[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}?$') {throw 'Expected an explicit GPO/domain/backup GUID.'}
    ([guid]$Value).ToString('D').ToLowerInvariant()
}
function Get-WelaGpoAuditKey {
    param([object[]]$Rows)
    $seen=@{};$parts=@()
    foreach($row in $Rows) {
        $guid=Get-WelaGpoGuid $row.Guid
        if($seen.ContainsKey($guid) -or [string]$row.Mask -cnotmatch '^[123]$') {throw 'Duplicate subcategory or unsupported audit mask in GPO content.'}
        $seen[$guid]=$true;$parts+=$guid+'='+[string]$row.Mask
    }
    (@($parts|Sort-Object) -join ';')
}
function Get-WelaGpoExpectedKey {
    param($Plan)
    Get-WelaGpoAuditKey @($Plan.Controls|Where-Object Disposition -eq Exported|ForEach-Object {[pscustomobject]@{Guid=$_.Guid;Mask=$_.ExportMask}})
}
function Read-WelaGpoPolicyReport {
    param([string]$Xml,[switch]$Blank,[switch]$AllowEnabled)
    $doc=Read-WelaGpoXml $Xml;$root=$doc.DocumentElement;$ns='http://www.microsoft.com/GroupPolicy/Settings'
    if($root.LocalName -cne 'GPO' -or $root.NamespaceURI -cne $ns) {throw 'Expected a native GPMC GPO report.'}
    Get-WelaGpoChildren $root @('Identifier','Name','IncludeComments','CreatedTime','ModifiedTime','ReadTime','SecurityDescriptor','FilterDataAvailable','FilterName','FilterDescription','Computer','User','LinksTo') -Repeated LinksTo
    $types='http://www.microsoft.com/GroupPolicy/Types'
    $id=Get-WelaGpoGuid (Get-WelaGpoText $root.Identifier 'Identifier' $types)
    $domain=Get-WelaGpoText $root.Identifier 'Domain' $types
    $name=Get-WelaGpoText $root 'Name'
    $rows=@();$precedence=0;$versions=@()
    foreach($side in @('Computer','User')) {
        $node=$root.$side
        if(-not $node) {throw 'Incomplete GPO report sides.'}
        Get-WelaGpoChildren $node @('VersionDirectory','VersionSysvol','Enabled','ExtensionData') -Repeated ExtensionData
        $enabled=Get-WelaGpoText $node 'Enabled'
        if($enabled -cnotin @('true','false') -or (-not $AllowEnabled -and $enabled -cne 'false')) {throw 'Both computer and user GPO settings must already be disabled.'}
        $ad=Get-WelaGpoText $node 'VersionDirectory';$sysvol=Get-WelaGpoText $node 'VersionSysvol'
        if($ad -notmatch '^\d{1,5}$' -or $sysvol -notmatch '^\d{1,5}$' -or [int]$ad -gt 65535 -or $ad -cne $sysvol) {throw 'GPO AD/SYSVOL versions are unknown or inconsistent.'}
        if($Blank -and $ad -ne '0') {throw 'New GPO is not at a blank version.'}
        $versions+=[int]$ad
        foreach($extensionData in @($node.SelectNodes("*[local-name()='ExtensionData']"))) {
            Get-WelaGpoChildren $extensionData @('Extension','Name')
            $extensions=@($extensionData.SelectNodes("*[local-name()='Extension']"))
            if($extensions.Count -ne 1 -or $side -eq 'User' -or $Blank) {throw 'User/blank GPO contains settings or ambiguous extensions.'}
            $extension=$extensions[0]
            foreach($setting in $extension.ChildNodes) {
                if($setting.NodeType -in @('Whitespace','Comment')) {continue}
                if($setting.LocalName -ceq 'AuditSetting' -and $setting.NamespaceURI -ceq ($ns+'/Auditing')) {
                    Get-WelaGpoChildren $setting @('PolicyTarget','SubcategoryName','SubcategoryGuid','SettingValue')
                    if((Get-WelaGpoText $setting 'PolicyTarget') -cne 'System') {throw 'Only system audit policy is supported.'}
                    $rows+=[pscustomobject]@{Guid=(Get-WelaGpoText $setting 'SubcategoryGuid');Mask=(Get-WelaGpoText $setting 'SettingValue')}
                } elseif($setting.LocalName -ceq 'SecurityOptions' -and $setting.NamespaceURI -ceq ($ns+'/Security')) {
                    Get-WelaGpoChildren $setting @('KeyName','SettingNumber','Display')
                    if((Get-WelaGpoText $setting 'KeyName') -ine 'MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy' -or (Get-WelaGpoText $setting 'SettingNumber') -cne '1') {throw 'Unrelated security setting in GPO report.'}
                    $precedence++
                } else {throw "Unsupported GPO report policy extension: $($setting.NamespaceURI)/$($setting.LocalName)"}
            }
        }
    }
    if(($Blank -and ($rows.Count -or $precedence)) -or (-not $Blank -and ($precedence -ne 1 -or -not $rows.Count))) {throw 'GPO report lacks the exact selected audit/precedence policy.'}
    if($root.FilterName -or $root.FilterDescription) {throw 'WMI-filtered source/target GPOs are unsupported.'}
    [pscustomobject]@{Id=$id;Domain=$domain;Name=$name;AuditKey=(Get-WelaGpoAuditKey $rows);ComputerVersion=$versions[0];UserVersion=$versions[1];Links=@($root.SelectNodes("*[local-name()='LinksTo']")).Count;Disabled=($root.Computer.Enabled -ceq 'false' -and $root.User.Enabled -ceq 'false')}
}
function Test-WelaGpoPayload {
    param([string]$AuditText,[string]$TemplateText,[string]$ExpectedKey)
    $csv=@($AuditText|ConvertFrom-Csv -ErrorAction Stop)
    $header='Machine Name|Policy Target|Subcategory|Subcategory GUID|Inclusion Setting|Exclusion Setting|Setting Value'
    if(-not $csv.Count -or ($csv[0].PSObject.Properties.Name -join '|') -cne $header) {throw 'Unsupported native audit.csv schema.'}
    $rows=@()
    foreach($row in $csv) {
        if($row.'Machine Name' -or $row.'Policy Target' -cne 'System' -or $row.'Exclusion Setting') {throw 'Per-user, machine-targeted or exclusion audit rows are unsupported.'}
        $rows+=[pscustomobject]@{Guid=$row.'Subcategory GUID';Mask=$row.'Setting Value'}
    }
    if((Get-WelaGpoAuditKey $rows) -cne $ExpectedKey) {throw 'Actual audit.csv does not match the reviewed package.'}
    $section='';$sections=@{};$values=@{}
    foreach($raw in ($TemplateText -split '\r?\n')) {
        $line=$raw.Trim().TrimStart([char]0xFEFF)
        if(-not $line -or $line.StartsWith(';')) {continue}
        if($line -match '^\[([^\]]+)\]$') {
            $section=$matches[1]
            if($sections.ContainsKey($section) -or $section -notin @('Unicode','Version','Registry Values','System Access','Event Audit','Privilege Rights','Registry Keys','File Security','Service General Setting')) {throw 'Unknown/duplicate security template section.'}
            $sections[$section]=$true;continue
        }
        $key=$section+'|'+($line -split '=',2)[0].Trim()
        if($values.ContainsKey($key)) {throw 'Duplicate security template setting.'};$values[$key]=$line
        $accepted=switch($section) {
            Unicode {$line -match '^Unicode\s*=\s*yes$'}
            Version {$line -match '^(signature\s*=\s*"\$CHICAGO\$"|Revision\s*=\s*1)$'}
            'Registry Values' {$line -match '^MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\SCENoApplyLegacyAuditPolicy\s*=\s*4\s*,\s*1$'}
            default {$false}
        }
        if(-not $accepted) {throw 'Actual security template contains unrelated or mistyped settings.'}
    }
    if($values.Count -ne 4 -or -not $values.ContainsKey('Registry Values|MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy')) {throw 'Security template must contain only typed DWORD audit precedence and its header.'}
}
function Get-WelaGpoInventory {
    param([string]$Root,[switch]$Live)
    $prefix=$Root.TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar
    $files=@();$directories=@();$pending=New-Object 'System.Collections.Generic.Queue[string]';$pending.Enqueue($Root)
    while($pending.Count) {
        foreach($item in @(Get-ChildItem -LiteralPath $pending.Dequeue() -Force -ErrorAction Stop)) {
            if(([int]$item.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -or $item.Name -match ':') {throw 'GPO payload contains a reparse point or stream.'}
            $relative=$item.FullName.Substring($prefix.Length).Replace('\','/').ToLowerInvariant()
            if($item.PSIsContainer) {$directories+=$relative;$pending.Enqueue($item.FullName)}
            else {
                if($item.Length -gt 4194304) {throw 'GPO file exceeds 4 MiB.'}
                $files+=[pscustomobject]@{Path=$relative;Length=$item.Length;Sha256=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant();FullPath=$item.FullName}
            }
            if($files.Count+$directories.Count -gt 100) {throw 'GPO inventory exceeds the narrow policy limit.'}
        }
    }
    [pscustomobject]@{Files=$files;Directories=$directories}
}
function Test-WelaGpoInventory {
    param($Inventory,[switch]$Live,[switch]$Blank)
    $dirs=@('machine','user','machine/applications','machine/microsoft','machine/microsoft/windows nt','machine/microsoft/windows nt/audit','machine/microsoft/windows nt/secedit','machine/scripts','machine/scripts/startup','machine/scripts/shutdown','user/applications','user/scripts','user/scripts/logon','user/scripts/logoff')
    $payload=@('machine/microsoft/windows nt/audit/audit.csv','machine/microsoft/windows nt/secedit/gpttmpl.inf')
    $expected=if($Live) {if($Blank){@('gpt.ini')}else{@('gpt.ini')+$payload}} else {@('backup.xml','bkupinfo.xml','gpreport.xml')+@($payload|ForEach-Object {'domainsysvol/gpo/'+$_})}
    $allowedDirs=if($Live){$dirs}else{@('domainsysvol','domainsysvol/gpo')+@($dirs|ForEach-Object {'domainsysvol/gpo/'+$_})}
    if(@($Inventory.Directories|Where-Object {$_ -notin $allowedDirs}).Count -or @($Inventory.Files|Where-Object Path -notin $expected).Count -or $Inventory.Files.Count -ne $expected.Count) {throw 'Backup/SYSVOL must contain exactly the narrow audit payload and native metadata; unknown files/directories/settings are refused.'}
}
function Assert-WelaGpoBackupMetadata {
    param([string]$Xml,[string]$BackupInfoXml,[string]$BackupId,$Report,$Inventory)
    $doc=Read-WelaGpoXml $Xml;$ns='http://www.microsoft.com/GroupPolicy/GPOOperations';$root=$doc.DocumentElement
    if($root.LocalName -cne 'GroupPolicyBackupScheme' -or $root.NamespaceURI -cne $ns -or $root.GetAttribute('version',$ns) -cne '2.0' -or $root.GetAttribute('type',$ns) -cne 'GroupPolicyBackupTemplate') {throw 'Unsupported native backup format.'}
    Get-WelaGpoChildren $root @('GroupPolicyObject');$gpo=$root.GroupPolicyObject
    Get-WelaGpoChildren $gpo @('SecurityGroups','FilePaths','GroupPolicyCoreSettings','GroupPolicyExtension') -Repeated GroupPolicyExtension
    if(@($gpo.FilePaths.ChildNodes|Where-Object NodeType -eq Element).Count) {throw 'Backup path migration is unsupported.'}
    $core=$gpo.GroupPolicyCoreSettings
    Get-WelaGpoChildren $core @('ID','Domain','SecurityDescriptor','DisplayName','Options','UserVersionNumber','MachineVersionNumber','MachineExtensionGuids','UserExtensionGuids','WMIFilter')
    if((Get-WelaGpoGuid (Get-WelaGpoText $core 'ID')) -ne $Report.Id -or (Get-WelaGpoText $core 'Domain') -ine $Report.Domain -or (Get-WelaGpoText $core 'DisplayName') -cne $Report.Name -or (Get-WelaGpoText $core 'Options') -cne '3' -or (Get-WelaGpoText $core 'UserExtensionGuids') -or (Get-WelaGpoText $core 'WMIFilter')) {throw 'Backup identity, disabled flags, user extensions or WMI filter differ from the reviewed source.'}
    foreach($side in @('Machine','User')) {
        $v=Get-WelaGpoText $core ($side+'VersionNumber');$value=[uint32]0
        if(-not [uint32]::TryParse($v,[ref]$value) -or ($value -band 65535) -ne ($value -shr 16)) {throw 'Backup core version halves are inconsistent.'}
        $expected=if($side -eq 'Machine'){$Report.ComputerVersion}else{$Report.UserVersion}
        if(($value -band 65535) -ne $expected) {throw 'Backup core/report version mismatch.'}
    }
    $extensionText=Get-WelaGpoText $core 'MachineExtensionGuids'
    $allowedGuids=@('827d319e-6eac-11d2-a4ea-00c04f79f83a','803e14a0-b4fb-11d0-a0d0-00a0c90f574b','f3ccc681-b74c-4060-9f26-cd84525dca2a','0f3f3735-573d-9804-99e4-ab2a69ba5fd4')
    if($extensionText -notmatch '^(\[(\{[0-9A-Fa-f-]{36}\}){2,3}\]){2}$') {throw 'Unsupported machine extension registration.'}
    $registered=@([regex]::Matches($extensionText,'\{([^}]+)\}')|ForEach-Object {$_.Groups[1].Value.ToLowerInvariant()})
    if(@($registered|Where-Object {$_ -notin $allowedGuids}).Count -or $registered -notcontains $allowedGuids[0] -or $registered -notcontains $allowedGuids[2]) {throw 'Unrelated machine extension registration.'}
    $registeredCses=@{}
    foreach($group in [regex]::Matches($extensionText,'\[([^\]]+)\]')) {
        $parts=@([regex]::Matches($group.Groups[1].Value,'\{([^}]+)\}')|ForEach-Object {$_.Groups[1].Value.ToLowerInvariant()})
        $cse=$parts[0];$tools=if($cse -eq $allowedGuids[0]){@($allowedGuids[1])}elseif($cse -eq $allowedGuids[2]){@($allowedGuids[3],$allowedGuids[1])}else{throw 'Unsupported client-side extension position.'}
        if($registeredCses.ContainsKey($cse) -or @($parts[1..($parts.Count-1)]|Where-Object {$_ -notin $tools}).Count -or @($parts|Select-Object -Unique).Count -ne $parts.Count) {throw 'Unexpected extension/tool registration.'}
        $registeredCses[$cse]=$true
    }
    $seenFiles=@{}
    foreach($extension in @($gpo.SelectNodes("*[local-name()='GroupPolicyExtension']"))) {
        $id=Get-WelaGpoGuid $extension.GetAttribute('ID',$ns)
        if($id -notin @('827d319e-6eac-11d2-a4ea-00c04f79f83a','f3ccc681-b74c-4060-9f26-cd84525dca2a','f15c46cd-82a0-4c2d-a210-5d0d3182a418')) {throw 'Unknown native backup extension.'}
        Get-WelaGpoChildren $extension @('FSObjectFile','FSObjectDir') -Repeated @('FSObjectFile','FSObjectDir')
        foreach($node in $extension.ChildNodes|Where-Object NodeType -eq Element) {
            foreach($attribute in $node.Attributes) {if($attribute.NamespaceURI -cne $ns -or $attribute.LocalName -cnotin @('Path','SourceExpandedPath','Location','ReEvaluateFunction')) {throw 'Unknown backup filesystem directive.'}}
            if(@($node.ChildNodes|Where-Object NodeType -eq Element).Count) {throw 'Nested filesystem directives are unsupported.'}
            $location=$node.GetAttribute('Location',$ns).Replace('\','/').ToLowerInvariant()
            $path=$node.GetAttribute('Path',$ns).Replace('\','/').ToLowerInvariant()
            if(-not $location.StartsWith('domainsysvol/gpo/machine/')) {throw 'Only explicit machine-relative backup paths are supported.'}
            $relative=$location.Substring('domainsysvol/gpo/machine/'.Length)
            if($path -cne ('%gpo_mach_fspath%/'+$relative)) {throw 'Backup filesystem path/location mismatch.'}
            $sourcePath=$node.GetAttribute('SourceExpandedPath',$ns)
            if($sourcePath -notmatch '^\\\\[^\\]+\\sysvol\\[^\\]+\\Policies\\\{[0-9A-Fa-f-]{36}\}\\Machine\\' -or -not $sourcePath.EndsWith(('\Machine\'+$relative.Replace('/','\')),[StringComparison]::OrdinalIgnoreCase)) {throw 'Unsupported source filesystem reference.'}
            $reEvaluate=$node.GetAttribute('ReEvaluateFunction',$ns)
            if($reEvaluate -and ($relative -ne 'microsoft/windows nt/secedit/gpttmpl.inf' -or $reEvaluate -cne 'SecurityValidateSettings')) {throw 'Unknown native backup callback.'}
            if($node.LocalName -eq 'FSObjectDir') {if($location -notin $Inventory.Directories) {throw 'Backup references a missing/unknown directory.'}}
            else {if($location -notin $Inventory.Files.Path -or $seenFiles.ContainsKey($location)) {throw 'Backup references a missing/duplicate/unknown file.'};$seenFiles[$location]=$true}
        }
    }
    if($seenFiles.Count -ne 2) {throw 'Backup must reference exactly its two policy payloads.'}
    $info=(Read-WelaGpoXml $BackupInfoXml).DocumentElement;$ins='http://www.microsoft.com/GroupPolicy/GPOOperations/Manifest'
    if($info.LocalName -cne 'BackupInst' -or $info.NamespaceURI -cne $ins) {throw 'Unknown backup instance metadata.'}
    Get-WelaGpoChildren $info @('GPOGuid','GPODomain','GPODomainGuid','GPODomainController','BackupTime','ID','Comment','GPODisplayName')
    if((Get-WelaGpoGuid (Get-WelaGpoText $info 'ID')) -ne $BackupId -or (Get-WelaGpoGuid (Get-WelaGpoText $info 'GPOGuid')) -ne $Report.Id -or (Get-WelaGpoText $info 'GPODomain') -ine $Report.Domain -or (Get-WelaGpoText $info 'GPODisplayName') -cne $Report.Name) {throw 'Backup instance ID is not the source GPO ID, or metadata identities differ.'}
}
function Read-WelaGpoCreateConfig {
    param([string]$Path)
    $full=Resolve-WelaEvtxPath $Path
    if((Get-Item -LiteralPath $full -ErrorAction Stop).Length -gt 65536) {throw 'GPO creation config exceeds 64 KiB.'}
    $text=[IO.File]::ReadAllText($full);$config=ConvertFrom-WelaEvtxJson $text
    Assert-WelaEvtxObject $config @('SchemaVersion','PackagePath','BackupRoot','BackupId','Domain','DomainGuid','Dc','Name','ReviewedSha256')
    if(($config.SchemaVersion -isnot [int] -and $config.SchemaVersion -isnot [long]) -or $config.SchemaVersion -ne 1) {throw 'Unsupported GPO creation config schema.'}
    foreach($field in @('PackagePath','BackupRoot','BackupId','Domain','DomainGuid','Dc','Name','ReviewedSha256')) {if($config.$field -isnot [string]) {throw "Expected a string: $field"}}
    foreach($field in @('Domain','Dc')) {
        $address=$null
        if($config.$field -notmatch '^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$' -or [Net.IPAddress]::TryParse($config.$field,[ref]$address)) {throw 'Domain and DC must be exact DNS names, not IP addresses, URLs or aliases.'}
    }
    $config.BackupId=Get-WelaGpoGuid $config.BackupId;$config.DomainGuid=Get-WelaGpoGuid $config.DomainGuid
    if($config.Name -notmatch '^[A-Za-z0-9][A-Za-z0-9 _.()-]{0,126}[A-Za-z0-9)]$' -or $config.Name -match '^Default (Domain|Domain Controllers) Policy$') {throw 'Use a unique, plain 2-128 character GPO name; default policies are forbidden.'}
    if($config.ReviewedSha256 -and $config.ReviewedSha256 -cnotmatch '^[a-f0-9]{64}$') {throw 'ReviewedSha256 must be empty for Review or an exact lowercase SHA-256.'}
    foreach($field in @('PackagePath','BackupRoot')) {
        $pathValue=$config.$field
        if(-not [IO.Path]::IsPathRooted($pathValue)) {$pathValue=Join-Path (Split-Path $full -Parent) $pathValue}
        $config.$field=Resolve-WelaEvtxPath $pathValue
    }
    [pscustomobject]@{Config=$config;Path=$full;Sha256=(Get-WelaGpoBytesHash ([IO.File]::ReadAllBytes($full)))}
}
function Assert-WelaGpmResult {
    param($Result)
    if($null -eq $Result -or -not [Runtime.InteropServices.Marshal]::IsComObject($Result)) {throw 'Expected a native GPMC result, not a deserialized or fabricated status.'}
    # HRESULT S_OK is normally projected as void; failure HRESULTs throw COMException.
    # If the interop projection exposes a value, only typed integral S_OK is accepted.
    $status=$Result.OverallStatus()
    if($null -ne $status -and (($status -isnot [int] -and $status -isnot [long]) -or $status -ne 0)) {throw 'Native GPMC OverallStatus did not report S_OK.'}
}
function New-WelaGpm {
    if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {throw 'GPO creation/review requires native Windows GPMC; no domain operation was attempted.'}
    New-Object -ComObject GPMgmt.GPM -ErrorAction Stop
}
function Get-WelaGpoNativeBackup {
    param([string]$Root,[string]$Id)
    $gpm=New-WelaGpm;$constants=$gpm.GetConstants();$backup=$gpm.GetBackupDir($Root).GetBackup('{'+$Id+'}')
    if((Get-WelaGpoGuid ([string]$backup.ID)) -ne $Id) {throw 'GPMC returned another backup instance.'}
    $result=$backup.GenerateReport($constants.ReportXML)
    Assert-WelaGpmResult $result
    if($result.Result -isnot [string]) {throw 'Native GPMC backup report was not XML text.'}
    [pscustomobject]@{Gpm=$gpm;Backup=$backup;Xml=[string]::Concat($result.Result);Id=$Id}
}
function Get-WelaGpoCreateInput {
    param($Config)
    $null=ConvertFrom-WelaEvtxJson ([IO.File]::ReadAllText((Join-Path $Config.PackagePath 'manifest.json')))
    $package=Test-WelaGpoPackage $Config.PackagePath
    $folder=Join-Path $Config.BackupRoot ('{'+$Config.BackupId+'}')
    $folder=Resolve-WelaEvtxPath $folder
    if(-not (Test-Path -LiteralPath $folder -PathType Container)) {throw 'Selected backup instance directory does not exist; specify the backup ID, not its source GPO ID.'}
    $inventory=Get-WelaGpoInventory $folder;Test-WelaGpoInventory $inventory
    $files=@{};foreach($file in $inventory.Files){$files[$file.Path]=$file.FullPath}
    $report=Read-WelaGpoPolicyReport ([IO.File]::ReadAllText($files['gpreport.xml']))
    $key=Get-WelaGpoExpectedKey $package.Plan
    if($report.AuditKey -cne $key) {throw 'Cached GPMC report does not match the selected package.'}
    Assert-WelaGpoBackupMetadata ([IO.File]::ReadAllText($files['backup.xml'])) ([IO.File]::ReadAllText($files['bkupinfo.xml'])) $Config.BackupId $report $inventory
    Test-WelaGpoPayload ([IO.File]::ReadAllText($files['domainsysvol/gpo/machine/microsoft/windows nt/audit/audit.csv'])) ([IO.File]::ReadAllText($files['domainsysvol/gpo/machine/microsoft/windows nt/secedit/gpttmpl.inf'])) $key
    $native=Get-WelaGpoNativeBackup $Config.BackupRoot $Config.BackupId
    $nativeReport=Read-WelaGpoPolicyReport $native.Xml
    if(($nativeReport|ConvertTo-Json -Compress) -cne ($report|ConvertTo-Json -Compress)) {throw 'Native GPMC backup report differs from its validated metadata/content.'}
    $controlFiles=@()
    $manifestPath=Join-Path $Config.BackupRoot 'manifest.xml'
    if(Test-Path -LiteralPath $manifestPath) {
        $manifestPath=Resolve-WelaEvtxPath $manifestPath;$item=Get-Item -LiteralPath $manifestPath -ErrorAction Stop
        if($item.PSIsContainer -or $item.Length -gt 4194304) {throw 'Invalid or oversized native backup manifest.'}
        $controlFiles+=@([pscustomobject]@{Path='manifest.xml';FullPath=$manifestPath;Length=$item.Length;Sha256=(Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()})
    }
    $fingerprints=@($inventory.Files|Sort-Object Path|ForEach-Object {$_.Path+'|'+$_.Length+'|'+$_.Sha256})
    $packageInventory=Get-WelaGpoInventory $Config.PackagePath
    $fingerprints+=@($packageInventory.Files|Sort-Object Path|ForEach-Object {'package/'+$_.Path+'|'+$_.Length+'|'+$_.Sha256})
    $fingerprints+=@($controlFiles|ForEach-Object {'native-root/'+$_.Path+'|'+$_.Length+'|'+$_.Sha256})
    $fingerprints+=@($inventory.Directories|Sort-Object|ForEach-Object {'directory/'+$_})
    $fingerprint=Get-WelaGpoBytesHash ([Text.Encoding]::UTF8.GetBytes(($fingerprints -join "`n")))
    [pscustomobject]@{Fingerprint=$fingerprint;Package=$package;Inventory=$inventory;PackageInventory=$packageInventory;ControlFiles=$controlFiles;Source=$report;Native=$native;ExpectedKey=$key;NativeReportXml=$native.Xml}
}
function Open-WelaGpoCreationSession {
    param($Config)
    if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {throw 'GPO domain operations require Windows.'}
    $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if($computer.PartOfDomain -ne $true -or $computer.Domain -ine $Config.Domain) {throw 'A host joined to the explicitly selected domain is required; workgroup/cross-domain execution is refused.'}
    $session=Open-WelaAdSession $Config.Dc
    try {
        if(-not $session.Writable) {throw 'The pinned DC is read-only.'}
        $expectedDn=(@($Config.Domain.Split('.')|ForEach-Object {'DC='+$_}) -join ',')
        if($session.DomainDn -ine $expectedDn) {throw 'Pinned DC serves a different domain.'}
        $entry=@(Search-WelaAdDirectory $session $session.DomainDn -Attributes @('objectGUID'))
        if($entry.Count -ne 1 -or ([guid]::new([byte[]](Get-WelaAdSingleValue $entry[0] 'objectGUID'))).ToString('D') -ine $Config.DomainGuid) {throw 'Actual domain GUID differs from the reviewed identity.'}
        # A cross-domain GPO link is possible. Refuse multi-domain forests instead of claiming
        # a forest-wide negative from the pinned DC's one domain partition.
        $domains=@(Search-WelaAdDirectory $session ('CN=Partitions,'+$session.ConfigurationDn) '(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2))' Subtree @('nCName'))
        if($domains.Count -ne 1 -or (Get-WelaAdSingleValue $domains[0] 'nCName') -ine $session.DomainDn) {throw 'Only a verified single-domain forest is supported for complete domain/site link checks.'}
        $gpm=New-WelaGpm;$domain=$gpm.GetDomain($Config.Domain,$Config.Dc,0)
        [pscustomobject]@{Ad=$session;Gpm=$gpm;Domain=$domain;Identity=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;DomainGuid=$Config.DomainGuid;Dc=$Config.Dc}
    } catch {$session.Connection.Dispose();throw}
}
function Close-WelaGpoCreationSession {param($Session) if($Session -and $Session.Ad){$Session.Ad.Connection.Dispose()}}
function Get-WelaGpoNameMatches {
    param($Session,[string]$Name)
    # Config name grammar excludes LDAP-filter metacharacters except parentheses; encode all five.
    $escaped=$Name.Replace('\','\5c').Replace('*','\2a').Replace('(','\28').Replace(')','\29').Replace([string][char]0,'\00')
    @(Search-WelaAdDirectory $Session.Ad ('CN=Policies,CN=System,'+$Session.Ad.DomainDn) ('(&(objectClass=groupPolicyContainer)(displayName='+$escaped+'))') OneLevel @('objectGUID','displayName'))
}
function Get-WelaGpoNativeTarget {
    param($Session,$Config,[string]$Id,[switch]$Blank,[switch]$AllowEnabled)
    $gpo=$Session.Domain.GetGPO('{'+$Id+'}')
    if((Get-WelaGpoGuid ([string]$gpo.ID)) -ne $Id -or [string]$gpo.DisplayName -cne $Config.Name -or (-not $AllowEnabled -and ($gpo.IsComputerEnabled() -ne $false -or $gpo.IsUserEnabled() -ne $false)) -or $gpo.IsACLConsistent() -ne $true) {throw 'New GPO identity, disabled status or ACL consistency changed.'}
    $result=$gpo.GenerateReport($Session.Gpm.GetConstants().ReportXML);Assert-WelaGpmResult $result
    $xml=[string]::Concat($result.Result);$report=Read-WelaGpoPolicyReport $xml -Blank:$Blank -AllowEnabled:$AllowEnabled
    if($report.Id -ne $Id -or $report.Domain -ine $Config.Domain -or $report.Name -cne $Config.Name -or $report.Links) {throw 'Native target report identity or links changed.'}
    foreach($base in @($Session.Ad.DomainDn,('CN=Sites,'+$Session.Ad.ConfigurationDn))) {
        $links=@(Search-WelaAdDirectory $Session.Ad $base ('(gPLink=*{'+$Id+'}*)') Subtree @('gPLink'))
        if($links.Count) {throw 'A domain/OU/site link to the new GPO appeared; no further import is allowed.'}
    }
    $dn='CN={'+$Id+'},CN=Policies,CN=System,'+$Session.Ad.DomainDn
    $entry=@(Search-WelaAdDirectory $Session.Ad $dn -Attributes @('objectGUID','displayName','description','flags','versionNumber','gPCWQLFilter','gPCMachineExtensionNames','gPCUserExtensionNames','gPCFileSysPath','uSNChanged'))
    if($entry.Count -ne 1) {throw 'Target GPO AD object is missing/ambiguous.'}
    $e=$entry[0];$flags=Get-WelaAdSingleValue $e 'flags';$version=Get-WelaAdSingleValue $e 'versionNumber'
    if(($flags -cnotin @('0','1','2','3')) -or (-not $AllowEnabled -and $flags -cne '3') -or $version -notmatch '^\d+$' -or [uint32]$version -ne (([uint32]$report.UserVersion -shl 16)+[uint32]$report.ComputerVersion) -or $e.Values['gPCWQLFilter'] -or $e.Values['gPCUserExtensionNames']) {throw 'Target flags, versions or filters changed.'}
    if($Blank -and ($e.Values['gPCMachineExtensionNames'] -or $version -ne '0')) {throw 'Fresh target already contains extension settings.'}
    $nativePath=Get-WelaAdSingleValue $e 'gPCFileSysPath'
    $expectedPath='\\'+$Config.Domain+'\SysVol\'+$Config.Domain+'\Policies\{'+$Id+'}'
    if($nativePath -ine $expectedPath) {throw 'Unexpected target SYSVOL policy path.'}
    $path='\\'+$Config.Dc+'\SYSVOL\'+$Config.Domain+'\Policies\{'+$Id+'}'
    $inventory=Get-WelaGpoInventory $path -Live;Test-WelaGpoInventory $inventory -Live -Blank:$Blank
    $iniFile=@($inventory.Files|Where-Object Path -eq 'gpt.ini')[0]
    $ini=[IO.File]::ReadAllText($iniFile.FullPath)
    if($ini -notmatch '(?im)^Version\s*=\s*(\d+)\s*$' -or [uint32]$matches[1] -ne [uint32]$version) {throw 'Live GPT.INI version differs from AD/report.'}
    if(-not $Blank) {
        $audit=@($inventory.Files|Where-Object {$_.Path -like '*/audit.csv'})[0];$inf=@($inventory.Files|Where-Object {$_.Path -like '*/gpttmpl.inf'})[0]
        Test-WelaGpoPayload ([IO.File]::ReadAllText($audit.FullPath)) ([IO.File]::ReadAllText($inf.FullPath)) $report.AuditKey
    }
    # Preserve the permission descriptor rendered by native GPMC; no ACL writes.
    $reportDoc=Read-WelaGpoXml $xml
    $sddlNodes=@($reportDoc.SelectNodes("//*[local-name()='SecurityDescriptor']/*[local-name()='SDDL' and namespace-uri()='http://www.microsoft.com/GroupPolicy/Types/Security']"))
    if($sddlNodes.Count -ne 1 -or -not $sddlNodes[0].InnerText) {throw 'Native GPO permission descriptor is unknown.'}
    [pscustomobject]@{Id=$Id;Name=$report.Name;Description=(Get-WelaAdSingleValue $e 'description');Disabled=$report.Disabled;Links=0;AuditKey=$report.AuditKey;ComputerVersion=$report.ComputerVersion;UserVersion=$report.UserVersion;Permissions=$sddlNodes[0].InnerText;Usn=(Get-WelaAdSingleValue $e 'uSNChanged');ObjectGuid=([guid]::new([byte[]](Get-WelaAdSingleValue $e 'objectGUID'))).ToString('D');Xml=$xml;Inventory=@($inventory.Files|Select-Object Path,Length,Sha256)}
}
function New-WelaGpoNativeTarget {
    param($Session,$Config,[string]$Marker)
    Import-Module GroupPolicy -ErrorAction Stop
    # New-GPO rejects a duplicate display name. No -CreateIfNeeded, name fallback or pre-existing GUID.
    $created=New-GPO -Name $Config.Name -Comment $Marker -Domain $Config.Domain -Server $Config.Dc -ErrorAction Stop
    Get-WelaGpoGuid ([string]$created.Id)
}
function Disable-WelaGpoNativeTarget {
    param($Session,$Config,[string]$Id,[string]$Marker)
    $initial=Get-WelaGpoNativeTarget $Session $Config $Id -Blank -AllowEnabled
    if($initial.Description -cne $Marker) {throw 'New GPO ownership marker changed before disabling.'}
    $gpo=$Session.Domain.GetGPO('{'+$Id+'}')
    if((Get-WelaGpoGuid ([string]$gpo.ID)) -ne $Id) {throw 'GPMC returned another new GPO.'}
    $null=$gpo.SetComputerEnabled($false)
    $fresh=Get-WelaGpoNativeTarget $Session $Config $Id -Blank -AllowEnabled
    if($fresh.Description -cne $Marker -or $fresh.ObjectGuid -cne $initial.ObjectGuid -or $fresh.Permissions -cne $initial.Permissions) {throw 'New GPO changed while disabling its empty settings.'}
    $null=$gpo.SetUserEnabled($false)
}
function Import-WelaGpoNativeTarget {
    param($Session,[string]$Id,$Backup)
    $gpo=$Session.Domain.GetGPO('{'+$Id+'}')
    $result=$gpo.Import(0,$Backup)
    Assert-WelaGpmResult $result
}
function Write-WelaGpoReceipt {
    param([string]$Root,[string]$Name,$Value)
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $Value -Depth 20))
    $stream=[IO.File]::Open((Join-Path $Root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)} finally {$stream.Dispose()}
}
function Protect-WelaGpoOutput {
    param([string]$Path)
    if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {return}
    $acl=New-Object Security.AccessControl.DirectorySecurity;$acl.SetAccessRuleProtection($true,$false)
    foreach($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')|Select-Object -Unique) {
        $rule=New-Object Security.AccessControl.FileSystemAccessRule([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow');$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}
function Copy-WelaGpoReviewedBackup {
    param($InputState,[string]$Root,[string]$BackupId)
    # Copy unchanged genuine bytes into the protected receipt directory. Never synthesize
    # Backup.xml or alter an archived policy to make it pass validation.
    $stage=Join-Path $Root 'reviewed-backup';$instance=Join-Path $stage ('{'+$BackupId+'}')
    $null=New-Item -ItemType Directory -Path $instance -ErrorAction Stop
    foreach($directory in $InputState.Inventory.Directories|Sort-Object Length) {
        $null=New-Item -ItemType Directory -Path (Join-Path $instance $directory) -ErrorAction Stop
    }
    foreach($file in $InputState.Inventory.Files) {[IO.File]::Copy($file.FullPath,(Join-Path $instance $file.Path),$false)}
    foreach($file in $InputState.ControlFiles) {[IO.File]::Copy($file.FullPath,(Join-Path $stage $file.Path),$false)}
    $stage
}
function Assert-WelaGpoCreateSource {
    param($State)
    $fresh=Read-WelaGpoCreateConfig $State.ConfigSource.Path
    if($fresh.Sha256 -cne $State.ConfigSource.Sha256) {throw 'Reviewed creation config changed.'}
    $input=Get-WelaGpoCreateInput $fresh.Config
    if($input.Fingerprint -cne $State.Input.Fingerprint) {throw 'Reviewed backup/package source changed.'}
    $input
}
function Get-WelaGpoCreationState {
    param($State)
    $null=Assert-WelaGpoCreateSource $State
    $session=Open-WelaGpoCreationSession $State.Config
    try {
        if($session.Identity -cne $State.OperatorSid) {throw 'Authenticated operator identity changed.'}
        $matches=@(Get-WelaGpoNameMatches $session $State.Config.Name)
        if(-not $State.Id) {if($matches.Count) {throw 'Requested new GPO name already exists; it will never be overwritten.'};return [pscustomobject]@{Exists=$false;DomainGuid=$session.DomainGuid;Dc=$session.Dc;OperatorSid=$session.Identity}}
        if($matches.Count -ne 1) {throw 'Created GPO name is no longer unique.'}
        $target=Get-WelaGpoNativeTarget $session $State.Config $State.Id
        if($target.Description -cne $State.Marker -or $target.ObjectGuid -cne $State.Blank.ObjectGuid -or $target.Permissions -cne $State.Blank.Permissions -or $target.AuditKey -cne $State.Input.ExpectedKey -or $target.UserVersion -lt $State.Blank.UserVersion -or $target.ComputerVersion -le $State.Blank.ComputerVersion) {throw 'Imported target identity, permissions, content or versions differ from the approved candidate.'}
        if($State.Verified -and ($target|ConvertTo-Json -Depth 15 -Compress) -cne ($State.Verified|ConvertTo-Json -Depth 15 -Compress)) {
            # Native ReadTime changes every report. Compare only stable evidence below instead.
            if((Get-WelaGpoTargetKey $target) -cne (Get-WelaGpoTargetKey $State.Verified)) {throw 'Created GPO changed after import verification.'}
        }
        if(-not $State.Verified){$State.Verified=$target}
        [pscustomobject]@{Exists=$true;VerifiedCandidate=$true;Target=$target}
    } finally {Close-WelaGpoCreationSession $session}
}
function Get-WelaGpoTargetKey {
    param($Target)
    $Target|Select-Object Id,Name,Description,Disabled,Links,AuditKey,ComputerVersion,UserVersion,Permissions,Usn,ObjectGuid,Inventory|ConvertTo-Json -Depth 12 -Compress
}
function Invoke-WelaGpoCreateCommand {
    param([ValidateSet('Review','Plan','Create')][string]$Action='Review',[string]$ConfigPath,[switch]$Auto,[switch]$DryRun,[string]$BackupPath)
    if($Action -ne 'Create' -and ($Auto -or $DryRun -or $BackupPath)) {throw 'Auto, DryRun and BackupPath require GpoCreateAction Create.'}
    if($Action -eq 'Create' -and -not $BackupPath) {throw 'Create requires an explicit fresh local BackupPath for durable receipts.'}
    if([string]::IsNullOrWhiteSpace($ConfigPath)) {throw 'GpoCreateConfigPath is required.'}
    $source=Read-WelaGpoCreateConfig $ConfigPath;$config=$source.Config;$input=Get-WelaGpoCreateInput $config
    if($Action -ne 'Review' -and $config.ReviewedSha256 -cne $input.Fingerprint) {throw 'Plan/Create require ReviewedSha256 from the reviewed native backup/package content.'}
    $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaDisabledUnlinkedGpoCreation';Action=$Action;ExitCode=0;Status='ReviewedInputsOnly';ReviewedSha256=$input.Fingerprint;ConfigSha256=$source.Sha256;BackupId=$config.BackupId;SourceGpoId=$input.Source.Id;SourceName=$input.Source.Name;ObservedDomain=$null;Domain=$config.Domain;DomainGuid=$config.DomainGuid;Dc=$config.Dc;Name=$config.Name;Profile=$input.Package.Plan;CreatedGpoId=$null;Configuration=$null;DeploymentVerified=$false;SigmaEvtxCredit=0;Limits=@('Native Windows audit policy and precedence only; Sysmon excluded.','No link, enable, assignment, client refresh, existing-GPO overwrite, deletion or automatic rollback.','Only a single-domain forest is supported; domain/OU/site links are freshly checked on the pinned writable DC.','Readback is scoped to the pinned DC and moment; replication, client application, events and positive real-domain acceptance remain separate.');OutputPath=$null}
    if($Action -eq 'Review') {return $report}
    $session=Open-WelaGpoCreationSession $config
    try {
        if(@(Get-WelaGpoNameMatches $session $config.Name).Count) {throw 'Requested GPO name already exists.'}
        $sid=$session.Identity
        $report.ObservedDomain=[pscustomobject]@{DomainGuid=$session.DomainGuid;PinnedWritableDc=$session.Dc;OperatorSid=$sid;ObservedUtc=[DateTime]::UtcNow.ToString('o');SingleDomainForest=$true}
    } finally {Close-WelaGpoCreationSession $session}
    $report.Status='PlanValidated';if($Action -eq 'Plan'){return $report}
    $output=Resolve-WelaEvtxPath $BackupPath
    if(Test-Path -LiteralPath $output) {throw 'Create requires a fresh output directory.'}
    if(-not (Test-Path -LiteralPath (Split-Path $output -Parent) -PathType Container)) {throw 'Output parent must already exist.'}
    $context=New-WelaConfigurationContext -Auto:$Auto -DryRun:$DryRun -BackupPath $output
    $state=@{ConfigSource=$source;Config=$config;Input=$input;OperatorSid=$sid;Id=$null;Marker=('WELA disabled unlinked candidate '+[guid]::NewGuid().ToString('D'));Blank=$null;Verified=$null;Output=$output}
    if(-not $DryRun) {Protect-WelaGpoOutput $output;Write-WelaGpoReceipt $output 'reviewed-plan.json' $report;$report.OutputPath=$output}
    $read={param($s) Get-WelaGpoCreationState $s}
    $compliant={param($current,$s) $current.Exists -and $current.VerifiedCandidate}
    $apply={param($s)
        $fresh=Assert-WelaGpoCreateSource $s
        # Hold all reviewed inputs against write/delete during native import. Added entries are
        # independently detected by full re-inventory immediately before mutation and after it.
        $locks=New-Object 'System.Collections.Generic.List[IDisposable]';$session=$null
        try {
            foreach($path in @($s.ConfigSource.Path)+@($fresh.Inventory.Files.FullPath)+@($fresh.PackageInventory.Files.FullPath)+@($fresh.ControlFiles|ForEach-Object FullPath)) {$locks.Add([IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read))}
            $fresh=Assert-WelaGpoCreateSource $s
            $stage=Copy-WelaGpoReviewedBackup $fresh $s.Output $s.Config.BackupId
            $stageConfig=$s.Config|Select-Object *;$stageConfig.BackupRoot=$stage
            $staged=Get-WelaGpoCreateInput $stageConfig
            if($staged.Fingerprint -cne $fresh.Fingerprint) {throw 'Protected backup copy differs from reviewed bytes.'}
            foreach($path in @($staged.Inventory.Files.FullPath)+@($staged.ControlFiles|ForEach-Object FullPath)) {$locks.Add([IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read))}
            $session=Open-WelaGpoCreationSession $s.Config
            if($session.Identity -cne $s.OperatorSid -or @(Get-WelaGpoNameMatches $session $s.Config.Name).Count) {throw 'New-GPO precondition changed.'}
            Write-WelaGpoReceipt $s.Output 'creation-intent.json' ([ordered]@{Domain=$s.Config.Domain;Dc=$s.Config.Dc;DomainGuid=$s.Config.DomainGuid;Name=$s.Config.Name;Marker=$s.Marker;ReviewedSha256=$fresh.Fingerprint;OperatorSid=$s.OperatorSid;Recovery='If creation returns no GUID, search the exact name/comment on this DC. Never delete or change an unrelated GPO.'})
            $s.Id=New-WelaGpoNativeTarget $session $s.Config $s.Marker
            # Record identity before any import; failure leaves an empty, unlinked GPO. No deletion.
            Write-WelaGpoReceipt $s.Output 'created-gpo.json' ([ordered]@{Id=$s.Id;DomainGuid=$s.Config.DomainGuid;Domain=$s.Config.Domain;Dc=$s.Config.Dc;Name=$s.Config.Name;Marker=$s.Marker;Status='CreatedEmpty_DisableAndImportNotYetVerified'})
            Close-WelaGpoCreationSession $session;$session=Open-WelaGpoCreationSession $s.Config
            if($session.Identity -cne $s.OperatorSid) {throw 'Operator identity changed before disabling.'}
            Disable-WelaGpoNativeTarget $session $s.Config $s.Id $s.Marker
            $s.Blank=Get-WelaGpoNativeTarget $session $s.Config $s.Id -Blank
            if($s.Blank.Description -cne $s.Marker) {throw 'New GPO ownership marker changed.'}
            Write-WelaGpoReceipt $s.Output 'blank-target.json' $s.Blank
            $null=Assert-WelaGpoCreateSource $s
            Close-WelaGpoCreationSession $session;$session=Open-WelaGpoCreationSession $s.Config
            if($session.Identity -cne $s.OperatorSid -or @(Get-WelaGpoNameMatches $session $s.Config.Name).Count -ne 1) {throw 'Import identity/name precondition changed.'}
            $blank=Get-WelaGpoNativeTarget $session $s.Config $s.Id -Blank
            if((Get-WelaGpoTargetKey $blank) -cne (Get-WelaGpoTargetKey $s.Blank)) {throw 'Fresh blank target changed before import.'}
            Write-WelaGpoReceipt $s.Output 'import-intent.json' ([ordered]@{Target=$blank;BackupId=$s.Config.BackupId;ReviewedSha256=$fresh.Fingerprint;Scope='Import only into this disabled, empty, unlinked new GUID; native GPMC flags 0, no migration table.'})
            $stagedFresh=Get-WelaGpoCreateInput $stageConfig
            if($stagedFresh.Fingerprint -cne $fresh.Fingerprint) {throw 'Protected backup changed before import.'}
            Import-WelaGpoNativeTarget $session $s.Id $stagedFresh.Native.Backup
            $null=Assert-WelaGpoCreateSource $s
        } finally {Close-WelaGpoCreationSession $session;foreach($lock in $locks){$lock.Dispose()}}
    }
    Invoke-WelaConfigurationControl -Context $context -Id 'GPO/CreateDisabledUnlinked' -Kind 'NewDomainGpo' -Target @{Domain=$config.Domain;DomainGuid=$config.DomainGuid;Dc=$config.Dc;Name=$config.Name} -Desired @{ReviewedSha256=$input.Fingerprint;BothSidesDisabled=$true;Links=0} -Read $read -Compliant $compliant -Apply $apply -CallbackState $state -Description 'Create a NEW disabled unlinked audit-policy candidate. Failure retains its GUID and evidence; no automatic deletion.'
    $configuration=Complete-WelaConfiguration -Context $context -Scope 'disabled-unlinked-gpo-creation-only' -SuccessMessage 'New disabled, unlinked GPO content verified on the selected DC; deployment remains unverified.'
    $report.Configuration=$configuration;$report.ExitCode=$configuration.ExitCode;$report.CreatedGpoId=$state.Id
    $report.Status=if($configuration.ExitCode){'Failed_ReviewRetainedReceipts'}elseif($DryRun){'DryRun_NoGpoCreated'}elseif($configuration.Skipped){'Declined_NoGpoCreated'}else{'DisabledUnlinkedCandidateVerified'}
    if(-not $DryRun){Write-WelaGpoReceipt $output 'result.json' $report}
    return $report
}
