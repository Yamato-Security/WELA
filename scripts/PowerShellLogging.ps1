# Scoped machine policy for the built-in Windows PowerShell 5.1 engine.
function ConvertTo-WelaPsLoggingKey { param($Value) ConvertTo-Json -InputObject $Value -Depth 24 -Compress }
function Assert-WelaPsLoggingSelection {
    param([string]$Action,[string[]]$Control,[string[]]$ModuleName)
    if ($null -eq $Control) {$Control=@()}; if ($null -eq $ModuleName) {$ModuleName=@()}
    if ($Action -ne 'Audit' -and -not $Control.Count) { throw 'Plan and Configure require explicit PowerShellLoggingControl selection.' }
    if (@($Control | ForEach-Object {$_.ToLowerInvariant()} | Select-Object -Unique).Count -ne $Control.Count -or @($Control | Where-Object {$_ -notin @('ScriptBlock','Module')}).Count) { throw 'Select unique ScriptBlock and/or Module controls.' }
    if ($ModuleName.Count -and $Control -notcontains 'Module') { throw 'Module names require explicit Module selection.' }
    if ($Action -ne 'Audit' -and $Control -contains 'Module' -and -not $ModuleName.Count) { throw 'Module selection requires explicit PowerShellLoggingModuleName values; use * only after reviewing all-module scope.' }
    if ($ModuleName.Count -gt 32 -or @($ModuleName | ForEach-Object {$_.ToLowerInvariant()} | Select-Object -Unique).Count -ne $ModuleName.Count) { throw 'Select at most 32 unique module names.' }
    foreach ($name in $ModuleName) {
        if ($name -cne '*' -and $name -cnotmatch '^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$') { throw 'Use literal module names or the explicitly selected * all-module value; paths and other wildcard patterns are refused.' }
    }
}
function Get-WelaPsLoggingTree {
    param([ValidateSet('LocalMachine','CurrentUser')][string]$Hive,[ValidateSet('Registry64','Registry32')][string]$View,[string]$Root)
    $base=$null;$rows=New-Object 'System.Collections.Generic.List[object]';$queue=New-Object 'System.Collections.Generic.Queue[string]';$queue.Enqueue('')
    try {
        $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::$Hive,[Microsoft.Win32.RegistryView]::$View)
        while ($queue.Count) {
            if ($rows.Count -ge 64) { throw 'PowerShell policy tree exceeds 64 keys; no partial snapshot is accepted.' }
            $relative=$queue.Dequeue();$path=$Root;if ($relative) {$path+='\'+$relative};$key=$null
            try {
                $key=$base.OpenSubKey($path,$false)
                if (-not $key) { if ($relative) {throw 'Policy key disappeared during enumeration.'};return [pscustomobject]@{Exists=$false;Keys=@()} }
                $names=@($key.GetValueNames()|Sort-Object);$children=@($key.GetSubKeyNames()|Sort-Object)
                if ($names.Count -gt 128 -or $children.Count -gt 64) {throw 'PowerShell policy key inventory is too large.'}
                $values=@(foreach ($name in $names) {[pscustomobject][ordered]@{Name=$name;Type=$key.GetValueKind($name).ToString();Value=$key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}})
                $acl=if ($PSVersionTable.PSVersion.Major -ge 6) {[Microsoft.Win32.RegistryAclExtensions]::GetAccessControl($key)}else{$key.GetAccessControl()}
                $rows.Add([pscustomobject][ordered]@{Path=$relative;Values=$values;Children=$children;Access=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]'Owner,Group,Access')})
                foreach ($child in $children) {$next=if($relative){$relative+'\'+$child}else{$child};if($next.Split('\').Count -gt 8){throw 'PowerShell policy tree exceeds eight levels.'};$queue.Enqueue($next)}
            } finally {if($key){$key.Dispose()}}
        }
        $result=[pscustomobject]@{Exists=$true;Keys=@($rows.ToArray()|Sort-Object Path)}
        if ((ConvertTo-WelaPsLoggingKey $result).Length -gt 1048576) {throw 'PowerShell policy snapshot exceeds one Mi character bound.'}
        return $result
    } finally {if($base){$base.Dispose()}}
}
function Get-WelaPsLoggingSources {
    $root=Split-Path $PSScriptRoot -Parent
    @(foreach ($name in @('WELA.ps1','scripts/PowerShellLogging.ps1','scripts/Configuration.ps1')) {[pscustomobject]@{Path=$name;Sha256=(Get-FileHash -LiteralPath (Join-Path $root $name) -Algorithm SHA256).Hash.ToLowerInvariant()}})
}
function Get-WelaPsLoggingSnapshot {
    if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess) {throw 'Use native 64-bit PowerShell on Windows.'}
    foreach($service in @('Winmgmt','EventLog')) {if((Get-Service -Name $service -ErrorAction Stop).Status -ne 'Running'){throw "$service must already be running; no service is started."}}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try {if(-not $identity.User -or $identity.ImpersonationLevel -ne [Security.Principal.TokenImpersonationLevel]::None){throw 'An actual non-impersonated process identity is required.'};$operator=[pscustomobject]@{Sid=$identity.User.Value;ImpersonationLevel=[string]$identity.ImpersonationLevel}}finally{$identity.Dispose()}
    $os=Get-CimInstance Win32_OperatingSystem -Property BuildNumber,ProductType -ErrorAction Stop
    $computer=Get-CimInstance Win32_ComputerSystem -Property Name,Domain,DomainRole,PartOfDomain -ErrorAction Stop
    if ([string]$os.BuildNumber -notmatch '^\d+$' -or $computer.PartOfDomain -isnot [bool] -or $computer.DomainRole -notin @(0,1,2,3,4,5)) {throw 'Complete actual Windows role/build/join context is required.'}
    $build=[int]$os.BuildNumber;$product=[int]$os.ProductType;$role=[int]$computer.DomainRole;$joined=$computer.PartOfDomain
    $coherent=($product -eq 1 -and (($role -eq 0 -and -not $joined) -or ($role -eq 1 -and $joined))) -or ($product -eq 3 -and (($role -eq 2 -and -not $joined) -or ($role -eq 3 -and $joined))) -or ($product -eq 2 -and $role -in @(4,5) -and $joined)
    if (-not $coherent -or [string]::IsNullOrWhiteSpace($computer.Name)) {throw 'Native host role observations conflict.'}
    if (-not (($product -eq 1 -and $build -in @(22000,22621,22631,26100,26200)) -or ($product -in @(2,3) -and $build -in @(20348,26100)))) {throw 'Windows role/build is outside reviewed scope.'}
    $engine=Get-WelaRegistryState 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine' PowerShellVersion
    if (-not $engine.ValueExists -or $engine.Type -cne 'String' -or $engine.Value -notmatch '^5\.1(?:\.|$)') {throw 'Installed Windows PowerShell 5.1 is not confirmed.'}
    $exe=Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $engineHash=(Get-FileHash -LiteralPath $exe -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    if (-not (Get-WelaRegistryState 'HKLM:\SOFTWARE\Policies\Microsoft\Windows' '__WelaObservationOnly').KeyExists) {throw 'Existing Microsoft Windows policy parent key is required; unrecorded ancestors will not be created.'}
    $windowsRoot='SOFTWARE\Policies\Microsoft\Windows\PowerShell';$coreRoot='SOFTWARE\Policies\Microsoft\PowerShellCore'
    $machine=Get-WelaPsLoggingTree LocalMachine Registry64 $windowsRoot;$user=Get-WelaPsLoggingTree CurrentUser Registry64 $windowsRoot
    if ((ConvertTo-WelaPsLoggingKey $machine) -cne (ConvertTo-WelaPsLoggingKey (Get-WelaPsLoggingTree LocalMachine Registry32 $windowsRoot)) -or (ConvertTo-WelaPsLoggingKey $user) -cne (ConvertTo-WelaPsLoggingKey (Get-WelaPsLoggingTree CurrentUser Registry32 $windowsRoot))) {throw 'Shared Windows PowerShell policy views disagree.'}
    $coreMachine=Get-WelaPsLoggingTree LocalMachine Registry64 $coreRoot;$coreUser=Get-WelaPsLoggingTree CurrentUser Registry64 $coreRoot
    $protected=Get-WelaPsLoggingTree LocalMachine Registry64 'SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging'
    $channel=$null
    try {$channel=Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational' -ErrorAction Stop;$channelState=[pscustomobject]@{Name=[string]$channel.LogName;Enabled=[bool]$channel.IsEnabled;MaximumBytes=[long]$channel.MaximumSizeInBytes;Mode=[string]$channel.LogMode;Security=[string]$channel.SecurityDescriptor}}finally{if($channel -is [IDisposable]){$channel.Dispose()}}
    $patch=Get-WelaRegistryState 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' UBR
    if (-not $patch.ValueExists -or $patch.Type -ne 'DWord' -or $patch.Value -lt 0) {throw 'Exact native patch evidence is required.'}
    [pscustomobject][ordered]@{Operator=$operator;Host=[pscustomobject]@{Computer=[string]$computer.Name;Domain=[string]$computer.Domain;Build=$build;Patch=$patch.Value;ProductType=$product;DomainRole=$role;PartOfDomain=$joined;CertSvcPresent=[bool](Get-Service CertSvc -ErrorAction SilentlyContinue)};Engine=[pscustomobject]@{Target='Windows PowerShell 5.1';Version=$engine.Value;Path=$exe;Sha256=$engineHash;WelaHostVersion=$PSVersionTable.PSVersion.ToString()};Sources=@(Get-WelaPsLoggingSources);Machine=$machine;CurrentUser=$user;PowerShellCoreMachine=$coreMachine;PowerShellCoreUser=$coreUser;ProtectedEventLogging=$protected;Channel=$channelState}
}
function Get-WelaPsLoggingValue {
    param($Tree,[string]$Path,[string]$Name)
    $keys=@($Tree.Keys|Where-Object Path -ieq $Path)
    if ($keys.Count -gt 1) {throw 'Ambiguous policy key.'}
    if ($keys.Count -eq 1) {$rows=@($keys[0].Values|Where-Object Name -ieq $Name);if($rows.Count -gt 1){throw 'Ambiguous policy value.'};if($rows.Count){return $rows[0]}}
    return $null
}
function Get-WelaPsLoggingDefinitions {
    param([string[]]$Control,[string[]]$ModuleName)
    # Add selected module entries before enabling module logging. No existing name is removed.
    if ($Control -contains 'Module') {
        foreach ($name in @($ModuleName|Sort-Object)) {[pscustomobject]@{Control='Module';Path='ModuleLogging\ModuleNames';Name=$name;Type='String';Value=$name}}
        [pscustomobject]@{Control='Module';Path='ModuleLogging';Name='EnableModuleLogging';Type='DWord';Value=1}
    }
    if ($Control -contains 'ScriptBlock') {[pscustomobject]@{Control='ScriptBlock';Path='ScriptBlockLogging';Name='EnableScriptBlockLogging';Type='DWord';Value=1}}
}
function Test-WelaPsLoggingValue {param($Snapshot,$Definition) $value=Get-WelaPsLoggingValue $Snapshot.Machine $Definition.Path $Definition.Name;return $null -ne $value -and $value.Type -ceq $Definition.Type -and (ConvertTo-WelaPsLoggingKey $value.Value) -ceq (ConvertTo-WelaPsLoggingKey $Definition.Value)}
function Assert-WelaPsLoggingKnown {
    param($Snapshot,[array]$Definitions)
    foreach ($definition in $Definitions) {
        $value=Get-WelaPsLoggingValue $Snapshot.Machine $definition.Path $definition.Name
        if ($value -and ($value.Type -cne $definition.Type -or ($definition.Type -eq 'DWord' -and $value.Value -notin @(0,1)) -or ($definition.Type -eq 'String' -and $value.Value -cne $definition.Value))) {throw "Selected policy value has an unknown type/value or a name collision: $($definition.Path)/$($definition.Name)."}
    }
    if (@($Definitions|Where-Object Control -eq Module).Count) {
        foreach($key in @($Snapshot.Machine.Keys|Where-Object Path -ieq 'ModuleLogging\ModuleNames')) {foreach($value in $key.Values) {if($value.Type -cne 'String' -or [string]::IsNullOrWhiteSpace($value.Value)){throw 'Existing module-name policy contains an unsupported type/empty value; preserve and review it.'}}}
    }
}
function Set-WelaPsLoggingValue {
    param($Definition)
    if ($Definition.Path -notin @('ModuleLogging','ModuleLogging\ModuleNames','ScriptBlockLogging')) {throw 'Unsupported policy destination.'}
    if (($Definition.Path -eq 'ModuleLogging' -and ($Definition.Name -cne 'EnableModuleLogging' -or $Definition.Type -cne 'DWord' -or $Definition.Value -ne 1)) -or ($Definition.Path -eq 'ScriptBlockLogging' -and ($Definition.Name -cne 'EnableScriptBlockLogging' -or $Definition.Type -cne 'DWord' -or $Definition.Value -ne 1))) {throw 'Unsupported logging DWORD mutation.'}
    if ($Definition.Path -eq 'ModuleLogging\ModuleNames') {Assert-WelaPsLoggingSelection Configure @('Module') @($Definition.Name);if($Definition.Type -cne 'String' -or $Definition.Value -cne $Definition.Name){throw 'Unsupported module-name mutation.'}}
    $base=$null;$key=$null
    try {$base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64);$key=$base.CreateSubKey('SOFTWARE\Policies\Microsoft\Windows\PowerShell\'+$Definition.Path);$key.SetValue($Definition.Name,$Definition.Value,[Microsoft.Win32.RegistryValueKind]::$($Definition.Type));$key.Flush()}
    finally{if($key){$key.Dispose()};if($base){$base.Dispose()}}
}
function Assert-WelaPsLoggingTransition {
    param($Before,$After,$Definition)
    foreach($property in $Before.PSObject.Properties.Name|Where-Object {$_ -cne 'Machine'}) {if((ConvertTo-WelaPsLoggingKey $Before.$property) -cne (ConvertTo-WelaPsLoggingKey $After.$property)){throw "Unselected state changed: $property"}}
    if (-not (Test-WelaPsLoggingValue $After $Definition)) {throw 'Selected policy value did not match native readback.'}
    $allowed=@('');$parts=$Definition.Path.Split('\');$part='';foreach($segment in $parts){$part=if($part){$part+'\'+$segment}else{$segment};$allowed+=$part}
    $old=@{};foreach($row in $Before.Machine.Keys){$old[$row.Path]=$row}
    $new=@{};foreach($row in $After.Machine.Keys){$new[$row.Path]=$row}
    foreach($path in $old.Keys){if(-not $new.ContainsKey($path)){throw 'An original policy key disappeared.'};if($new[$path].Access -cne $old[$path].Access){throw 'An existing policy key access descriptor changed.'}}
    foreach($path in $new.Keys){
        if(-not $old.ContainsKey($path) -and $path -notin $allowed){throw 'An unrequested policy key appeared.'}
        $expected=@();if($old.ContainsKey($path)){$expected=@($old[$path].Values|Where-Object {-not ($path -ieq $Definition.Path -and $_.Name -ieq $Definition.Name)})}
        $observed=@($new[$path].Values|Where-Object {-not ($path -ieq $Definition.Path -and $_.Name -ieq $Definition.Name)})
        if((ConvertTo-WelaPsLoggingKey $expected) -cne (ConvertTo-WelaPsLoggingKey $observed)){throw 'Unrelated policy values changed.'}
        $expectedChildren=@();if($old.ContainsKey($path)){$expectedChildren=@($old[$path].Children)}
        foreach($possible in $allowed){if(-not $possible){continue};$separator=$possible.LastIndexOf('\');$parent=if($separator -ge 0){$possible.Substring(0,$separator)}else{''};$leaf=if($separator -ge 0){$possible.Substring($separator+1)}else{$possible};if($parent -ieq $path){$expectedChildren+= $leaf}}
        if((ConvertTo-WelaPsLoggingKey @($expectedChildren|Sort-Object -Unique)) -cne (ConvertTo-WelaPsLoggingKey @($new[$path].Children|Sort-Object -Unique))){throw 'Unrelated policy subkeys changed.'}
    }
}
function Invoke-WelaPowerShellLogging {
    param([ValidateSet('Audit','Plan','Configure')][string]$Action='Audit',[string[]]$Control=@(),[string[]]$ModuleName=@(),[switch]$Auto,[switch]$DryRun,[string]$BackupPath,[string]$ResultsPath)
    Assert-WelaPsLoggingSelection $Action $Control $ModuleName
    if($Action -ne 'Configure' -and ($Auto -or $DryRun -or $BackupPath)){throw 'Consent, dry-run and backup options require PowerShellLoggingAction Configure.'}
    if($ResultsPath){$ResultsPath=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ResultsPath);if(Test-Path -LiteralPath $ResultsPath){throw 'ResultsPath must name a new file.'};if(-not (Test-Path -LiteralPath ([IO.Path]::GetDirectoryName($ResultsPath)) -PathType Container)){throw 'ResultsPath parent must already exist.'}}
    $definitions=@(Get-WelaPsLoggingDefinitions $Control $ModuleName);$before=$null;$diagnostic='';$known=$false
    try {$before=Get-WelaPsLoggingSnapshot;Assert-WelaPsLoggingKnown $before $definitions;$known=$true}catch{$diagnostic=$_.Exception.Message}
    $plan=[pscustomobject]@{Selection=@($Control);ModuleNames=@($ModuleName);Before=$before;Controls=@(foreach($definition in $definitions){[pscustomobject]@{Definition=$definition;Status=$(if(-not $known){'Unknown'}elseif(Test-WelaPsLoggingValue $before $definition){'AlreadyCompliant'}else{'ChangeRequired'})}});Status=$(if($known){'Observed'}else{'Unknown'});Diagnostic=$diagnostic;Provenance=@('https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings?view=powershell-5.1','https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-powershellexecutionpolicy');Meaning='Explicit Windows PowerShell 5.1 machine-policy selection. Existing module names remain active when Module logging is enabled; no claim of a complete Microsoft/CIS/ASD baseline.'}
    if($Action -eq 'Configure') {
        if(-not $known){$report=[pscustomobject]@{ExitCode=1;Scope='windows-powershell-event-logging-policy-only';Results=@();Diagnostic=$diagnostic}}
        else {
            $context=New-WelaConfigurationContext -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath
            $shared=@{Expected=$before;Definitions=$definitions;Failed=$false;StopReason=$null}
            foreach($definition in $definitions){
                if($shared.StopReason){$context.Results.Add([pscustomobject]@{Id=('PowerShellLogging/'+$definition.Path+'/'+$definition.Name);Kind='Registry';Target=@{Path=$definition.Path;Name=$definition.Name};Desired=@{Type=$definition.Type;Value=$definition.Value};Before=$null;After=$null;Status='Skipped';Diagnostic=$shared.StopReason});continue}
                $state=@{Shared=$shared;Definition=$definition}
                $read={param($s) if($s.Shared.Failed){throw 'An earlier operation failed; remaining operations are stopped.'};$snapshot=Get-WelaPsLoggingSnapshot;if((ConvertTo-WelaPsLoggingKey $snapshot) -cne (ConvertTo-WelaPsLoggingKey $s.Shared.Expected)){throw 'Policy, host, channel, engine or source changed from the reviewed state.'};Assert-WelaPsLoggingKnown $snapshot $s.Shared.Definitions;return $snapshot}
                $test={param($snapshot,$s) Test-WelaPsLoggingValue $snapshot $s.Definition}
                $apply={param($s)
                    try {$fresh=Get-WelaPsLoggingSnapshot;if((ConvertTo-WelaPsLoggingKey $fresh) -cne (ConvertTo-WelaPsLoggingKey $s.Shared.Expected)){throw 'Pre-write state drifted after journal/approval; no write attempted.'};Set-WelaPsLoggingValue $s.Definition;$after=Get-WelaPsLoggingSnapshot;Assert-WelaPsLoggingTransition $fresh $after $s.Definition;$s.Shared.Expected=$after;'Only the named Windows PowerShell policy value was changed and read back.'}catch{$s.Shared.Failed=$true;throw}
                }
                Invoke-WelaConfigurationControl -Context $context -Id ('PowerShellLogging/'+$definition.Path+'/'+$definition.Name) -Kind Registry -Target @{Hive='LocalMachine';View='Registry64';Path=('SOFTWARE\Policies\Microsoft\Windows\PowerShell\'+$definition.Path);Name=$definition.Name} -Desired @{Type=$definition.Type;Value=$definition.Value} -Read $read -Compliant $test -Apply $apply -CallbackState $state -Description 'Enable the explicitly selected event-logging policy; existing module names are preserved.'
                if($context.Results[$context.Results.Count-1].Status -eq 'Failed'){$shared.Failed=$true;$shared.StopReason='Not attempted because an earlier selected operation failed.'}
                if($context.Results[$context.Results.Count-1].Status -eq 'Skipped' -and -not $DryRun){$shared.StopReason='Not attempted because an earlier selected operation was declined.'}
            }
            $report=Complete-WelaConfiguration -Context $context -Scope 'windows-powershell-event-logging-policy-only' -SuccessMessage 'Selected local machine policy values verified; fresh-session events and policy persistence remain separate.'
        }
    }else{$report=[pscustomobject]@{ExitCode=$(if($known){0}else{1});Scope='windows-powershell-event-logging-policy-only'}}
    $report|Add-Member NoteProperty Action $Action;$report|Add-Member NoteProperty Plan $plan
    $report|Add-Member NoteProperty EventGeneration 'Unverified; run a separately reviewed new Windows PowerShell session and retain native XML.'
    $report|Add-Member NoteProperty PowerShell7Sessions 'Not assessed. Separate PowerShell Core policy/configuration and Windows-policy fallback are preserved; fallback users can inherit changed Windows settings.'
    $report|Add-Member NoteProperty PolicyAuthority 'Local registry observations only; GPO/MDM persistence and current winning authority are not established.'
    $report|Add-Member NoteProperty ReadyRuleCredit 0
    if($ResultsPath){$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($report|ConvertTo-Json -Depth 28));$file=[IO.File]::Open($ResultsPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$file.Write($bytes,0,$bytes.Length)}finally{$file.Dispose()}}
    return $report
}
