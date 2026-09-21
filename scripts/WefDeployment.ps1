# Domain/Kerberos source configuration and create-only collector subscriptions.
# All writes run through Configuration.ps1; assessment never grants Sigma credit.
function Get-WelaWefHost {
    $computer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    [pscustomobject]@{ DomainJoined=($computer.PartOfDomain -eq $true); Fqdn=([string]$computer.DNSHostName + '.' + [string]$computer.Domain); DomainRole=[int]$computer.DomainRole }
}

function Get-WelaWefControlState {
    param([string]$Kind, $Target)
    switch ($Kind) {
        'Service' {
            $service = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $Target.Name) -ErrorAction Stop
            if (-not $service -or $service.StartMode -notin @('Auto','Manual','Disabled') -or $service.State -notin @('Running','Stopped')) { throw 'Service state is absent, pending or unsupported.' }
            return [pscustomobject]@{ Name=$Target.Name; StartMode=[string]$service.StartMode; State=[string]$service.State }
        }
        'Wsman' {
            # The WSMan provider can offer to start WinRM when accessed. Audit/Plan
            # must remain read-only, so never enter it while the service is stopped.
            if ((Get-WelaWefControlState Service @{ Name='WinRM' }).State -ne 'Running') { throw 'WinRM is stopped; WSMan settings were not queried to avoid implicit service startup.' }
            $item = Get-Item -LiteralPath $Target.Path -ErrorAction Stop
            if (-not $item.PSObject.Properties['Value'] -or -not $item.PSObject.Properties['SourceOfValue']) { throw 'WSMan value/provenance is unreadable.' }
            return [pscustomobject]@{ Value=([string]$item.Value).ToLowerInvariant(); SourceOfValue=[string]$item.SourceOfValue }
        }
        'Readers' {
            $group = Get-LocalGroup -SID 'S-1-5-32-573' -ErrorAction Stop
            $members = @(Get-LocalGroupMember -Group $group -ErrorAction Stop)
            if (@($members | Where-Object { -not $_.SID }).Count) { throw 'Unreadable group membership; no additive write can be verified.' }
            return [pscustomobject]@{ GroupSid='S-1-5-32-573'; MemberSids=@($members | ForEach-Object { $_.SID.ToString() } | Sort-Object -Unique) }
        }
        'SubscriptionManager' { return Get-WelaRegistryState -Path $Target.Path -Name $Target.Name }
        'ForwardedEvents' { return Get-WelaNativeChannel -Name 'ForwardedEvents' }
        'Subscription' {
            $ids = @((Invoke-WelaNative -FilePath 'wecutil.exe' -Arguments @('es')).Output | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ })
            if ($ids -notcontains $Target.Id) { return [pscustomobject]@{ Exists=$false; Xml=$null; Key=$null; Definition=$null } }
            # Keep evidence as a plain string. Windows PowerShell 5.1's JSON
            # serializer expands ETS properties on strings (for example a test
            # reader's PSDrive/PSProvider graph), unlike modern PowerShell.
            $xml = [string]::Concat((Invoke-WelaNative -FilePath 'wecutil.exe' -Arguments @('gs',$Target.Id,'/f:xml')).Diagnostic)
            $model = ConvertFrom-WelaWefSubscription -Xml $xml -SourceSids $Target.SourceSids -Observed
            return [pscustomobject]@{ Exists=$true; Xml=$xml; Key=$model.Key; Definition=$model.Definition }
        }
        default { throw "Unsupported WEF control kind: $Kind" }
    }
}

function Get-WelaWefStateKey {
    param($Value)
    ConvertTo-Json -InputObject $Value -Depth 25 -Compress
}

function Test-WelaWefControl {
    param($Value, $Entry)
    switch ($Entry.Kind) {
        'Service' { return $Value.StartMode -eq 'Auto' -and $Value.State -eq 'Running' }
        'Wsman' { return $Value.Value -ceq $Entry.Desired.Value }
        'Readers' {
            $expected=@(@($Entry.Before.MemberSids) + 'S-1-5-20' | Sort-Object -Unique)
            return $Value.MemberSids -contains 'S-1-5-20' -and -not @(Compare-Object $expected @($Value.MemberSids)).Count
        }
        'SubscriptionManager' { return $Value.ValueExists -and $Value.Type -eq 'String' -and $Value.Value -ceq $Entry.Desired.Value }
        'ForwardedEvents' {
            return (Test-WelaNativeChannelSnapshot $Value) -and $Value.IsEnabled -and $Value.MaximumSizeInBytes -eq $Entry.Before.MaximumSizeInBytes -and
                $Value.LogMode -eq $Entry.Before.LogMode -and $Value.SecurityDescriptor -ceq $Entry.Before.SecurityDescriptor
        }
        'Subscription' { return $Value.Exists -and $Value.Key -ceq $Entry.Desired.Key }
    }
    return $false
}

function New-WelaWefEntry {
    param([string]$Kind, $Target, $Desired)
    $before=$null; $diagnostic=''
    try { $before = Get-WelaWefControlState -Kind $Kind -Target $Target } catch { $diagnostic=$_.ToString() }
    $entry = [pscustomobject]@{ Kind=$Kind; Target=$Target; Desired=$Desired; Before=$before; Status='Unknown'; Diagnostic=$diagnostic }
    if ($before) { $entry.Status = if (Test-WelaWefControl $before $entry) { 'RequestedSettingsMatch' } else { 'ChangeRequired' } }
    if ($Kind -eq 'Wsman' -and $before -and $before.SourceOfValue -and $entry.Status -ne 'RequestedSettingsMatch') { $entry.Status='ManualReview'; $entry.Diagnostic='Policy-owned WSMan value is not overwritten.' }
    if ($Kind -eq 'SubscriptionManager' -and $before.ValueExists -and $entry.Status -ne 'RequestedSettingsMatch') { $entry.Status='ManualReview'; $entry.Diagnostic='Selected slot already contains another value/type; select a free slot or manage its owning policy.' }
    if ($Kind -eq 'Subscription' -and $before.Exists -and $entry.Status -ne 'RequestedSettingsMatch') { $entry.Status='ManualReview'; $entry.Diagnostic='An existing different subscription is never updated or replaced.' }
    if ($Kind -eq 'Readers' -and $entry.Status -eq 'ChangeRequired') {
        try {
            if ((Get-WelaWefHost).DomainRole -in @(4,5)) { $entry.Status='ManualReview'; $entry.Diagnostic='Domain controller BUILTIN membership has AD/domain policy authority; WELA never changes it through this local workflow. Arrange and verify the forwarding identity membership separately.' }
        } catch { $entry.Status='Unknown'; $entry.Diagnostic='Host role cannot be verified for a safe local group update. ' + $_.ToString() }
    }
    return $entry
}

function Get-WelaWefHardeningEntries {
    param([string]$Role)
    if ($Role -eq 'Source') {
        New-WelaWefEntry Wsman @{ Path='WSMan:\localhost\Client\Auth\Digest' } @{ Value='false' }
    } else {
        New-WelaWefEntry Wsman @{ Path='WSMan:\localhost\Service\Auth\CbtHardeningLevel' } @{ Value='strict' }
        New-WelaWefEntry Wsman @{ Path='WSMan:\localhost\Shell\AllowRemoteShellAccess' } @{ Value='false' }
    }
}

function Test-WelaWefAdmx {
    # Verify the OS's actual SubscriptionManager list mapping before registry writes.
    $path = Join-Path $env:windir 'PolicyDefinitions/EventForwarding.admx'
    $doc = Read-WelaWefXml (Get-Content -LiteralPath $path -Raw -ErrorAction Stop)
    $policies = @($doc.SelectNodes("//*[local-name()='policy' and @name='SubscriptionManager']"))
    if ($policies.Count -ne 1 -or $policies[0].GetAttribute('class') -cne 'Machine') { throw 'Local EventForwarding ADMX SubscriptionManager policy is unsupported.' }
    $lists = @($policies[0].SelectNodes("./*[local-name()='elements']/*[local-name()='list']"))
    if ($lists.Count -ne 1 -or $lists[0].GetAttribute('key') -ine 'Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager' -or
        $lists[0].GetAttribute('valuePrefix') -ne '' -or $lists[0].GetAttribute('valueType') -notin @('','string')) { throw 'Local SubscriptionManager list mapping is unsupported; no guessed policy mapping is written.' }
    return $true
}

function Get-WelaWefCollectorPrerequisites {
    param($Config)
    $checks = @()
    try {
        $hostState=Get-WelaWefHost
        $ok=$hostState.DomainJoined -and $hostState.Fqdn -ieq $Config.CollectorFqdn -and $hostState.DomainRole -in @(2,3)
        $checks += [pscustomobject]@{ Name='Domain member server identity'; Verified=[bool]$ok; Evidence=$hostState; Diagnostic='Dedicated collector workload isolation is an operator prerequisite, not detected from domain role.' }
    } catch { $checks += [pscustomobject]@{ Name='Domain member server identity'; Verified=$false; Evidence=$null; Diagnostic=$_.ToString() } }
    try {
        if ((Get-WelaWefControlState Service @{ Name='WinRM' }).State -ne 'Running') { throw 'WinRM is stopped; listener enumeration was not attempted.' }
        $listeners = @(Get-WSManInstance -ResourceURI 'winrm/config/Listener' -Enumerate -ErrorAction Stop)
        $matched = @($listeners | Where-Object { $_.Address -ceq $Config.ListenerAddress -and $_.Transport -ieq 'HTTP' -and [string]$_.Port -eq '5985' -and [string]$_.Enabled -ieq 'true' -and $_.URLPrefix -ieq 'wsman' })
        $checks += [pscustomobject]@{ Name='Existing matching HTTP listener'; Verified=($matched.Count -eq 1); Evidence=@($listeners | Select-Object Address,Transport,Port,Enabled,URLPrefix,ListeningOn); Diagnostic='Listener definition only; reachability is not tested.' }
    } catch { $checks += [pscustomobject]@{ Name='Existing matching HTTP listener'; Verified=$false; Evidence=$null; Diagnostic=$_.ToString() } }
    try {
        $rules = @(Get-NetFirewallRule -Name $Config.IngressRuleName -PolicyStore ActiveStore -ErrorAction Stop)
        if ($rules.Count -ne 1) { throw 'Expected exactly one existing effective firewall rule.' }
        $rule=$rules[0]; $ports=@($rule | Get-NetFirewallPortFilter -ErrorAction Stop); $addresses=@($rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
        $scopeMatches=$addresses.Count -eq 1 -and
            (Test-WelaWefFirewallAddressSet $Config.IngressLocalAddresses @($addresses[0].LocalAddress)) -and
            (Test-WelaWefFirewallAddressSet $Config.IngressRemoteAddresses @($addresses[0].RemoteAddress))
        $ok=[string]$rule.Enabled -eq 'True' -and [string]$rule.Direction -eq 'Inbound' -and [string]$rule.Action -eq 'Allow' -and [string]$rule.Profile -eq 'Domain' -and
            $ports.Count -eq 1 -and [string]$ports[0].Protocol -in @('TCP','6') -and [string]$ports[0].LocalPort -eq '5985' -and $scopeMatches
        $checks += [pscustomobject]@{ Name='Existing scoped domain ingress rule'; Verified=[bool]$ok; Evidence=@{ Rule=($rule | Select-Object Name,Enabled,Direction,Action,Profile,PolicyStoreSourceType,EnforcementStatus); Ports=$ports | Select-Object Protocol,LocalPort,RemotePort; Addresses=$addresses | Select-Object LocalAddress,RemoteAddress }; Diagnostic='Exact selected rule definition only; other rules, network reachability and effective packet acceptance are not established.' }
    } catch { $checks += [pscustomobject]@{ Name='Existing scoped domain ingress rule'; Verified=$false; Evidence=$null; Diagnostic=$_.ToString() } }
    foreach ($name in @('WinRM','Wecsvc')) {
        $entry=New-WelaWefEntry Service @{ Name=$name } @{ StartMode='Auto'; State='Running' }
        $checks += [pscustomobject]@{ Name="$name service"; Verified=($entry.Status -eq 'RequestedSettingsMatch'); Evidence=$entry.Before; Diagnostic=$entry.Diagnostic }
    }
    foreach ($entry in @(Get-WelaWefHardeningEntries Collector)) { $checks += [pscustomobject]@{ Name=$entry.Target.Path; Verified=($entry.Status -eq 'RequestedSettingsMatch'); Evidence=$entry.Before; Diagnostic=$entry.Diagnostic } }
    $entry=New-WelaWefEntry Wsman @{ Path='WSMan:\localhost\Service\Auth\Kerberos' } @{ Value='true' }
    $checks += [pscustomobject]@{ Name='Collector Kerberos authentication'; Verified=($entry.Status -eq 'RequestedSettingsMatch'); Evidence=$entry.Before; Diagnostic=$entry.Diagnostic }
    return $checks
}

function Get-WelaWefPrerequisites {
    param($Model,[string]$Role)
    if ($Role -eq 'Collector') { return @(Get-WelaWefCollectorPrerequisites $Model.Config) }
    $checks=@()
    try { $hostState=Get-WelaWefHost; $checks += [pscustomobject]@{ Name='Source domain membership'; Verified=[bool]$hostState.DomainJoined; Evidence=$hostState; Diagnostic='' } }
    catch { $checks += [pscustomobject]@{ Name='Source domain membership'; Verified=$false; Evidence=$null; Diagnostic=$_.ToString() } }
    try { $valid=Test-WelaWefAdmx; $checks += [pscustomobject]@{ Name='Local SubscriptionManager ADMX mapping'; Verified=[bool]$valid; Evidence=$null; Diagnostic='' } }
    catch { $checks += [pscustomobject]@{ Name='Local SubscriptionManager ADMX mapping'; Verified=$false; Evidence=$null; Diagnostic=$_.ToString() } }
    $entries=@(New-WelaWefEntry Service @{ Name='WinRM' } @{ StartMode='Auto'; State='Running' })
    $entries+=@(Get-WelaWefHardeningEntries Source)
    $entries+=New-WelaWefEntry Wsman @{ Path='WSMan:\localhost\Client\Auth\Kerberos' } @{ Value='true' }
    $entries+=New-WelaWefEntry Readers @{ GroupSid='S-1-5-32-573' } @{ AddMemberSid='S-1-5-20' }
    foreach ($entry in $entries) { $checks += [pscustomobject]@{ Name=($entry.Kind + ':' + ($entry.Target | ConvertTo-Json -Compress)); Verified=($entry.Status -eq 'RequestedSettingsMatch'); Evidence=$entry.Before; Diagnostic=$entry.Diagnostic } }
    foreach ($channel in @($Model.Subscriptions | ForEach-Object { $_.Query.Channels } | Sort-Object -Unique)) {
        $observed=Get-WelaNativeChannel -Name $channel
        $checks += [pscustomobject]@{ Name=$channel; Verified=($observed.State -eq 'Enabled'); Evidence=$observed; Diagnostic='Channel enablement only; effective token access and event generation are not tested.' }
    }
    return $checks
}

function Set-WelaWefPrerequisiteCheck {
    param($Context,$Model,[string]$Role)
    $state=@{ Model=$Model; Role=$Role }
    $read={ param($state) return ,@(Get-WelaWefPrerequisites $state.Model $state.Role) }
    $test={ param($value,$state) return -not @($value | Where-Object { -not $_.Verified }).Count }
    $apply={ param($state) throw 'Required WEF prerequisites remain unmet; configure them explicitly and retry. No automatic topology changes were attempted.' }
    Invoke-WelaConfigurationControl -Context $Context -Id 'WEF/Prerequisites' -Kind WefPrerequisite -Target @{ Role=$Role } -Desired @{ AllVerified=$true } -Read $read -Compliant $test -Apply $apply -CallbackState $state
}

function Add-WelaWefFailure {
    param($Context,[string]$Id,[string]$Diagnostic,$Evidence)
    $Context.Results.Add([pscustomobject]@{ Id=$Id; Kind='WefPrerequisite'; Target=$null; Desired=$null; Before=$Evidence; After=$null; Status='Failed'; Diagnostic=$Diagnostic })
    Write-Host "[Failed] $Id $Diagnostic" -ForegroundColor Red
}

function Set-WelaWefEntry {
    param($Context, $Entry, $Config)
    if ($Entry.Status -in @('Unknown','ManualReview')) { Add-WelaWefFailure $Context $Entry.Kind $Entry.Diagnostic $Entry.Before; return }
    $state=@{ Entry=$Entry; Config=$Config; Initial=$true; Snapshot=$null; BackupPath=$Context.BackupPath }
    $read={
        param($state)
        $entry=$state.Entry; $current=Get-WelaWefControlState $entry.Kind $entry.Target
        if ($state.Initial) {
            if ((Get-WelaWefStateKey $current) -cne (Get-WelaWefStateKey $entry.Before)) { throw 'WEF control changed since planning; review a fresh plan.' }
            $state.Initial=$false; $state.Snapshot=$current
        }
        return $current
    }
    $test={ param($current,$state) Test-WelaWefControl $current $state.Entry }
    $apply={
        param($state)
        $entry=$state.Entry
        $fresh=Get-WelaWefControlState $entry.Kind $entry.Target
        if ((Get-WelaWefStateKey $fresh) -cne (Get-WelaWefStateKey $state.Snapshot)) { throw 'WEF control changed after the recovery snapshot; no write attempted.' }
        switch ($entry.Kind) {
            'Service' {
                if ($fresh.StartMode -ne 'Auto') { Set-Service -Name $entry.Target.Name -StartupType Automatic -ErrorAction Stop }
                if ($fresh.State -ne 'Running') { Start-Service -Name $entry.Target.Name -ErrorAction Stop }
            }
            'Wsman' {
                if ($fresh.SourceOfValue) { throw 'Policy-owned WSMan settings are not overwritten.' }
                Set-Item -LiteralPath $entry.Target.Path -Value $entry.Desired.Value -ErrorAction Stop
            }
            'Readers' {
                $hostState=Get-WelaWefHost
                if (-not $hostState.DomainJoined -or $hostState.DomainRole -notin @(1,3)) { throw 'Only a confirmed domain member workstation/server can receive a local Event Log Readers update; DC or unknown group authority requires manual administration.' }
                $group=Get-LocalGroup -SID 'S-1-5-32-573' -ErrorAction Stop
                Add-LocalGroupMember -Group $group -Member 'S-1-5-20' -ErrorAction Stop
                $after=Get-WelaWefControlState Readers $entry.Target
                $expected=@($fresh.MemberSids + 'S-1-5-20' | Sort-Object -Unique)
                if (@(Compare-Object $expected @($after.MemberSids)).Count) { throw 'Group membership changed beyond the requested additive NETWORK SERVICE member.' }
            }
            'SubscriptionManager' {
                $null=Test-WelaWefAdmx
                if ($fresh.ValueExists) { throw 'Existing SubscriptionManager values are not overwritten.' }
                New-WelaRegistryKey $entry.Target.Path
                # Recheck after key creation; a concurrent policy writer may populate the slot.
                if ((Get-WelaRegistryState $entry.Target.Path $entry.Target.Name).ValueExists) { throw 'SubscriptionManager slot was populated concurrently.' }
                New-ItemProperty -LiteralPath $entry.Target.Path -Name $entry.Target.Name -Value $entry.Desired.Value -PropertyType String -ErrorAction Stop | Out-Null
            }
            'ForwardedEvents' {
                if (-not (Test-WelaNativeChannelSnapshot $fresh)) { throw 'ForwardedEvents settings cannot be preserved from an unreadable snapshot.' }
                Invoke-WelaNative -FilePath 'wevtutil.exe' -Arguments @('sl','ForwardedEvents','/e:true')
                $after=Get-WelaWefControlState ForwardedEvents $entry.Target
                if ($after.MaximumSizeInBytes -ne $fresh.MaximumSizeInBytes -or $after.LogMode -ne $fresh.LogMode -or $after.SecurityDescriptor -cne $fresh.SecurityDescriptor) { throw 'ForwardedEvents buffer, mode or ACL drifted during enablement.' }
            }
            'Subscription' {
                $prerequisites=@(Get-WelaWefCollectorPrerequisites $state.Config)
                if (@($prerequisites | Where-Object { -not $_.Verified }).Count) { throw 'Collector prerequisites changed or remain unmet; subscription creation is blocked.' }
                if ($fresh.Exists) { throw 'Existing subscriptions are never overwritten.' }
                $file=Join-Path $state.BackupPath ('subscription-' + [guid]::NewGuid().ToString('N') + '.xml')
                $bytes=(New-Object Text.UTF8Encoding($false)).GetBytes($entry.Desired.Xml)
                $stream=[IO.File]::Open($file,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
                try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
                # Hold a read-sharing lock over the exact prepared XML throughout native import.
                $lock=[IO.File]::Open($file,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
                try {
                    $observedBytes=New-Object byte[] $lock.Length
                    if ($lock.Read($observedBytes,0,$observedBytes.Length) -ne $bytes.Length -or [Convert]::ToBase64String($observedBytes) -cne [Convert]::ToBase64String($bytes)) { throw 'Prepared subscription XML changed before import.' }
                    Invoke-WelaNative -FilePath 'wecutil.exe' -Arguments @('cs',$file)
                } finally { $lock.Dispose() }
            }
        }
    }
    Invoke-WelaConfigurationControl -Context $Context -Id ("WEF/{0}/{1}" -f $Entry.Kind,($Entry.Target | ConvertTo-Json -Compress)) -Kind $Entry.Kind -Target $Entry.Target -Desired $Entry.Desired -Read $read -Compliant $test -Apply $apply -CallbackState $state -Description 'Apply this explicitly selected native WEF setting; preserve unrelated configuration.'
}

function Get-WelaWefInventory {
    param($InputModel,[string]$Role)
    foreach ($subscription in $InputModel.Subscriptions) {
        $channels=@()
        foreach ($name in $subscription.Query.Channels) { $channels += Get-WelaNativeChannel -Name $name }
        $runtime=$null; $typedRuntime=$null; $observed=$null; $observationError=''
        if ($Role -eq 'Collector') {
            try { $observed=Get-WelaWefControlState Subscription @{ Id=$subscription.Id; SourceSids=$subscription.SourceSids } }
            catch { $observationError=$_.ToString() }
            try { $native=Invoke-WelaNative -FilePath 'wecutil.exe' -Arguments @('gr',$subscription.Id); $runtime=[pscustomobject]@{ State='CommandSucceeded'; Raw=$native.Diagnostic; Diagnostic='Localized native runtime status is retained without inferring event arrival.' } }
            catch { $runtime=[pscustomobject]@{ State='Unknown'; Raw=$null; Diagnostic=$_.ToString() } }
            try {$typedRuntime=Get-WelaWecRuntime -Id $subscription.Id}
            catch {$typedRuntime=[pscustomobject]@{Status='Unknown';Diagnostic=$_.Exception.Message;ReadyRuleCredit=0}}
        }
        [pscustomobject]@{ Id=$subscription.Id; RequestedEnabled=$subscription.Definition.Enabled; RequestedDefinition=$subscription.Definition; ObservedEnabled=$(if ($observed.Exists) { $observed.Definition.Enabled } else { $null }); ObservedSubscription=$observed; ObservationError=$observationError; Filters=$subscription.Query.Filters; SourceChannels=$channels; ChannelObservationLocation=$(if ($Role -eq 'Collector') { 'Collector only; remote source states are not observed' } else { 'Local source' }); Runtime=$runtime; TypedRuntime=$typedRuntime; EffectiveSourceReadAccess='Not tested'; EventArrival='Not tested'; ForwardedSigmaCoverage='Not assessed' }
    }
}

function Invoke-WelaWefCommand {
    param([ValidateSet('Source','Collector')][string]$Role,[ValidateSet('Audit','Plan','Configure')][string]$Action='Audit',
        [string]$ConfigPath,[switch]$Auto,[switch]$DryRun,[string]$BackupPath,[string]$ResultsPath)
    if (-not $ConfigPath) { throw '-WefConfigPath is required.' }
    $model=Import-WelaWefConfig -Path $ConfigPath -Role $Role; $config=$model.Config
    if ($env:OS -ne 'Windows_NT') { throw 'Native WEF commands require Windows.' }
    if ($DryRun -and $Action -ne 'Configure') { throw '-DryRun requires WefAction Configure; Audit and Plan are read-only.' }
    $scope=if ($Role -eq 'Source') { 'wef-source-configuration-only' } else { 'wec-collector-subscriptions-only' }
    $hostState=$null; $hostError=''
    try { $hostState=Get-WelaWefHost } catch { $hostError=$_.ToString() }
    $hostReady=$hostState -and $hostState.DomainJoined -and ($Role -eq 'Source' -or ($hostState.Fqdn -ieq $config.CollectorFqdn -and $hostState.DomainRole -eq 3))
    $entries=@(); $services=if ($Role -eq 'Source') { @('WinRM') } else { @('WinRM','Wecsvc') }
    foreach ($service in $services) { $entries += New-WelaWefEntry Service @{ Name=$service } @{ StartMode='Auto'; State='Running' } }
    $entries += @(Get-WelaWefHardeningEntries $Role)
    if ($Role -eq 'Source') {
        $entries += New-WelaWefEntry Readers @{ GroupSid='S-1-5-32-573' } @{ AddMemberSid='S-1-5-20' }
        $entries += New-WelaWefEntry SubscriptionManager @{ Path='HKLM:\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'; Name=[string]$config.SubscriptionManagerSlot } @{ Value=('Server={0},Refresh={1}' -f $config.CollectorUri,$config.RefreshSeconds) }
    } else {
        $entries += New-WelaWefEntry ForwardedEvents @{ Channel='ForwardedEvents' } @{ IsEnabled=$true }
        foreach ($subscription in $model.Subscriptions) { $entries += New-WelaWefEntry Subscription @{ Id=$subscription.Id; SourceSids=$subscription.SourceSids } @{ Key=$subscription.Key; Xml=$subscription.Xml } }
    }
    $channelPlan=@()
    if ($Role -eq 'Source' -and $config.ApplyChannelProfile) { $channelProfile=Get-WelaNativeChannelProfile; $channelPlan=@(Get-WelaNativeChannelPlan -Profile $channelProfile -GrantEventLogReaders:$config.GrantCapi2Read) }
    if ($Action -eq 'Configure') {
        $context=New-WelaConfigurationContext -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath
        if (-not $hostReady) { Add-WelaWefFailure $context HostIdentity ('Domain membership / collector member-server FQDN prerequisite is unmet. ' + $hostError) $hostState }
        else {
            # Service startup is separate from listeners/firewall configuration. No qc/remoting shortcut.
            foreach ($entry in @($entries | Where-Object Kind -eq 'Service')) { Set-WelaWefEntry $context $entry $config }
            foreach ($entry in @(Get-WelaWefHardeningEntries $Role)) {
                if ($config.Hardening -eq 'ApplyASD') { Set-WelaWefEntry $context $entry $config }
            }
            if ($Role -eq 'Source') {
                $admxReady=$false
                try { $admxReady=Test-WelaWefAdmx } catch { Add-WelaWefFailure $context SubscriptionManagerAdmx $_.ToString() $null }
                foreach ($entry in @($entries | Where-Object Kind -eq 'Readers')) {
                    if ($config.GrantNetworkServiceRead) { Set-WelaWefEntry $context $entry $config }
                }
                if ($channelPlan.Count) { Set-WelaNativeChannelControls -Context $context -Plan $channelPlan -Profile $channelProfile.id }
                if ($admxReady -and -not @($context.Results | Where-Object Status -eq 'Failed').Count) {
                    $sourcePrerequisites=@(Get-WelaWefPrerequisites $model Source)
                    if (@($sourcePrerequisites | Where-Object { -not $_.Verified }).Count) { Add-WelaWefFailure $context SourcePrerequisites 'SubscriptionManager configuration is blocked until local source prerequisites are verified.' $sourcePrerequisites }
                    else { foreach ($entry in @($entries | Where-Object Kind -eq 'SubscriptionManager')) { Set-WelaWefEntry $context $entry $config } }
                }
            } else {
                $prerequisites=@(Get-WelaWefCollectorPrerequisites $config)
                if (@($prerequisites | Where-Object { -not $_.Verified }).Count) { Add-WelaWefFailure $context CollectorPrerequisites 'Subscription creation is blocked until the explicit listener, ingress, service and ASD hardening prerequisites are verified.' $prerequisites }
                else {
                    foreach ($entry in @($entries | Where-Object Kind -eq 'ForwardedEvents')) { Set-WelaWefEntry $context $entry $config }
                    if (-not @($context.Results | Where-Object Status -eq 'Failed').Count) {
                        foreach ($subscription in $model.Subscriptions) {
                            $entry=New-WelaWefEntry Subscription @{ Id=$subscription.Id; SourceSids=$subscription.SourceSids } @{ Key=$subscription.Key; Xml=$subscription.Xml }
                            Set-WelaWefEntry $context $entry $config
                        }
                    }
                }
            }
        }
        Set-WelaWefPrerequisiteCheck $context $model $Role
        $report=Complete-WelaConfiguration -Context $context -Scope $scope -SuccessMessage 'Requested local WEF controls read back. Runtime source access and event arrival remain unverified.'
    } else { $report=[pscustomobject]@{ Scope=$scope; ExitCode=0; DryRun=$false } }
    $current=@()
    foreach ($entry in $entries) { $current += New-WelaWefEntry $entry.Kind $entry.Target $entry.Desired }
    $prerequisites=@(Get-WelaWefPrerequisites $model $Role)
    $inventory=@(Get-WelaWefInventory $model $Role)
    $unmet=@($current | Where-Object Status -ne 'RequestedSettingsMatch')
    $sourceChannelProblems=@($inventory | ForEach-Object SourceChannels | Where-Object State -ne 'Enabled')
    $localMatch=$hostReady -and -not $unmet.Count -and -not @($prerequisites | Where-Object { -not $_.Verified }).Count -and ($Role -ne 'Source' -or -not $sourceChannelProblems.Count)
    if ($Action -eq 'Configure' -and -not $DryRun -and -not $localMatch) { $report.ExitCode=1 }
    if ($Action -ne 'Configure' -and (-not $hostReady -or @($current | Where-Object Status -in @('Unknown','ManualReview')).Count)) { $report.ExitCode=1 }
    $report | Add-Member NoteProperty Action $Action
    $report | Add-Member NoteProperty Role $Role
    $report | Add-Member NoteProperty CollectorUri $config.CollectorUri
    $report | Add-Member NoteProperty HostIdentity $hostState
    $report | Add-Member NoteProperty LocalConfigurationStatus $(if ($localMatch) { 'RequestedSettingsMatch' } else { 'Incomplete' })
    $report | Add-Member NoteProperty Controls $current
    $report | Add-Member NoteProperty Prerequisites $prerequisites
    $report | Add-Member NoteProperty ChannelPlan $channelPlan
    $report | Add-Member NoteProperty Subscriptions $inventory
    $report | Add-Member NoteProperty UnverifiedPrerequisites @('Source identity authorization/group token refresh and effective channel read access','Domain trust/Kerberos, endpoint reachability and packet acceptance','Network logon rights, event generation, subscription runtime health and representative collector arrivals','GPO refresh persistence, collection capacity/retention and forwarded Sigma coverage')
    Write-Host "Local WEF configuration: $($report.LocalConfigurationStatus). Effective read access, event arrival and forwarded Sigma coverage are not verified." -ForegroundColor Yellow
    $current | Select-Object Kind,Target,Status,Diagnostic | Format-Table -AutoSize | Out-Host
    if ($ResultsPath) { try { $report | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $ResultsPath -Encoding UTF8 -ErrorAction Stop } catch { $report.ExitCode=1; Write-Host "[Failed] Writing WEF results: $_" -ForegroundColor Red } }
    return $report
}
