# Explicit creation of one new, narrowly scoped collector firewall rule.
function ConvertTo-WelaIngressAddress {
    param([string]$Value,[switch]$Remote,[switch]$Observed)
    if($Value -cnotmatch '^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]{1,2}|([0-9]{1,3}\.){3}[0-9]{1,3}))?$'){throw 'An exact canonical IPv4 address or remote /24-/32 network is required.'}
    $parts=$Value.Split('/');$octets=$parts[0].Split('.');$number=0L
    foreach($octet in $octets){if([int]$octet -gt 255 -or ([int]$octet).ToString() -cne $octet){throw 'Noncanonical IPv4 address.'};$number=($number -shl 8)+[int]$octet}
    if([int]$octets[0] -in @(0,127) -or [int]$octets[0] -ge 224 -or $parts[0] -eq '169.254.0.0'){throw 'Unspecified, loopback or multicast/reserved addresses are unsupported.'}
    $prefix=32
    if($parts.Count -eq 2){
        if(-not $Remote){throw 'Local addresses must be exact assigned IPv4 addresses.'}
        if($parts[1].Contains('.')){
            if(-not $Observed){throw 'Use a numeric CIDR prefix.'}
            $mask=0L;foreach($piece in $parts[1].Split('.')){if([int]$piece -gt 255){throw 'Invalid netmask.'};$mask=($mask -shl 8)+[int]$piece}
            $prefix=0;while($prefix -lt 32 -and ($mask -band (1L -shl (31-$prefix)))){$prefix++}
            $expected=if($prefix -eq 0){0L}else{(0xffffffffL -shl (32-$prefix)) -band 0xffffffffL}
            if($mask -ne $expected){throw 'Noncontiguous netmask.'}
        }else{$prefix=[int]$parts[1];if($prefix.ToString() -cne $parts[1]){throw 'Noncanonical prefix.'}}
        if($prefix -lt 24 -or $prefix -gt 32 -or ($number -band ((1L -shl (32-$prefix))-1)) -ne 0){throw 'Remote scopes require aligned /24-/32 networks.'}
    }
    if($prefix -eq 32){$parts[0]}else{$parts[0]+'/'+$prefix}
}
function Get-WelaIngressSelection {
    param([string]$Name,[object[]]$LocalAddresses,[object[]]$RemoteAddresses)
    if($Name -cnotmatch '^WELA-WEC-[A-Za-z0-9][A-Za-z0-9-]{0,63}$'){throw 'Rule name must start WELA-WEC- and contain only letters, digits and hyphens.'}
    if($LocalAddresses.Count -lt 1 -or $LocalAddresses.Count -gt 8 -or $RemoteAddresses.Count -lt 1 -or $RemoteAddresses.Count -gt 16){throw 'Select 1-8 local addresses and 1-16 remote scopes.'}
    $local=@();$remote=@()
    foreach($value in $LocalAddresses){if($value -isnot [string]){throw 'Address must be a string.'};$local+=ConvertTo-WelaIngressAddress $value}
    foreach($value in $RemoteAddresses){if($value -isnot [string]){throw 'Address must be a string.'};$remote+=ConvertTo-WelaIngressAddress $value -Remote}
    if(@($local|Select-Object -Unique).Count -ne $local.Count -or @($remote|Select-Object -Unique).Count -ne $remote.Count){throw 'Duplicate address scopes are unsupported.'}
    [pscustomobject][ordered]@{Name=$Name;LocalAddresses=@($local|Sort-Object);RemoteAddresses=@($remote|Sort-Object)}
}
function Get-WelaIngressSources {
    $root=Split-Path $PSScriptRoot -Parent;$sources=[ordered]@{}
    foreach($name in @('WELA.ps1','scripts/WecIngress.ps1','scripts/WecUpdate.ps1','scripts/WefArrival.ps1','scripts/ChannelRead.ps1','scripts/ChannelReadNative.cs','modules/AuditProfiles.psm1','scripts/CustomAuditProfiles.ps1')){
        $sources[$name]=(Get-FileHash -LiteralPath (Join-Path $root $name) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    }
    $sources|ConvertTo-Json -Compress
}
function Get-WelaIngressContext {
    $reader=Get-WelaChannelReader;$hostState=Get-WelaChannelReadHost
    if(-not $reader.ElevatedAdministrator -or $hostState.ProductType -ne 3 -or $hostState.DomainRole -notin @(2,3) -or $hostState.Build -notin @(20348,26100)){throw 'An elevated native Server 2022/2025 member or standalone collector is required.'}
    $services=@();foreach($name in @('BFE','MpsSvc','WinRM','Wecsvc')){
        $found=@(Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop)
        if($found.Count -ne 1 -or ($name -in @('BFE','MpsSvc') -and $found[0].State -ne 'Running')){throw 'Firewall services must run and WinRM/Wecsvc must be installed.'}
        $services+=[ordered]@{Name=$name;State=[string]$found[0].State;StartMode=[string]$found[0].StartMode}
    }
    $profiles=@(NetSecurity\Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop|Sort-Object Name|Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowInboundRules,AllowLocalFirewallRules)
    $domain=@($profiles|Where-Object Name -eq 'Domain')
    if($profiles.Count -ne 3 -or $domain.Count -ne 1 -or [string]$domain[0].Enabled -ne 'True' -or [string]$domain[0].AllowLocalFirewallRules -eq 'False' -or [string]$domain[0].AllowInboundRules -eq 'False'){throw 'Domain firewall must be enabled and permit local inbound rules.'}
    $addresses=@(NetTCPIP\Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop|Where-Object AddressState -eq 'Preferred'|ForEach-Object IPAddress|Sort-Object -Unique)
    [pscustomobject][ordered]@{Host=$hostState;MachineGuid=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid;Reader=[ordered]@{Sid=$reader.UserSid;Logon=$reader.AuthenticationId;Groups=$reader.GroupSids};Services=$services;Profiles=$profiles;Addresses=$addresses}
}
function Read-WelaIngressRules {
    param([string]$Store)
    $rules=@(NetSecurity\Get-NetFirewallRule -PolicyStore $Store -ErrorAction Stop|Select-Object -First 4097)
    if($rules.Count -gt 4096){throw 'Firewall inventory exceeds the 4096-rule bound.'}
    $rules
}
function Assert-WelaIngressAbsent {
    param([string]$Name)
    foreach($store in @('PersistentStore','ActiveStore')){if(@(Read-WelaIngressRules $store|Where-Object Name -eq $Name).Count){throw 'The selected rule name already exists; existing rules are never replaced.'}}
}
function New-WelaIngressNativeRule {
    param($Selection)
    $null=NetSecurity\New-NetFirewallRule -PolicyStore PersistentStore -Name $Selection.Name -DisplayName $Selection.Name -Description 'WELA reviewed collector ingress; TCP 5985, Domain profile, explicit IPv4 scopes.' -Group 'WELA reviewed collector ingress' -Enabled True -Profile Domain -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5985 -RemotePort Any -LocalAddress $Selection.LocalAddresses -RemoteAddress $Selection.RemoteAddresses -EdgeTraversalPolicy Block -LooseSourceMapping $false -LocalOnlyMapping $false -Authentication NotRequired -Encryption NotRequired -OverrideBlockRules $false -ErrorAction Stop
}
function Read-WelaIngressRule {
    param([string]$Store,[string]$Name)
    $rule=@(Read-WelaIngressRules $Store|Where-Object Name -eq $Name)
    if($rule.Count -ne 1){throw 'Exactly one selected rule must be observed.'}
    $r=$rule[0];$filters=[ordered]@{}
    foreach($kind in @('Port','Address','Application','Service','Interface','InterfaceType','Security')){
        $command='NetSecurity\Get-NetFirewall'+$kind+'Filter';$items=@(&$command -AssociatedNetFirewallRule $r -ErrorAction Stop)
        if($items.Count -ne 1){throw "Ambiguous $kind filter."};$filters[$kind]=$items[0]
    }
    [pscustomobject]@{Store=$Store;Rule=$r;Filters=$filters}
}
function ConvertTo-WelaIngressEvidence {
    param($Observed)
    # Project the inspected fields, not recursive CIM class/session metadata.
    $fields=[ordered]@{
        Rule=@('Name','DisplayName','Description','Group','Enabled','Profile','Direction','Action','EdgeTraversalPolicy','LooseSourceMapping','LocalOnlyMapping','PolicyStoreSourceType','Owner','Platform','PrimaryStatus','EnforcementStatus')
        Port=@('Protocol','LocalPort','RemotePort','IcmpType','DynamicTarget')
        Address=@('LocalAddress','RemoteAddress')
        Application=@('Program','Package')
        Service=@('Service');Interface=@('InterfaceAlias');InterfaceType=@('InterfaceType')
        Security=@('Authentication','Encryption','OverrideBlockRules','LocalUser','RemoteUser','RemoteMachine')
    }
    $result=[ordered]@{Store=$Observed.Store}
    foreach($kind in $fields.Keys){
        $item=if($kind -eq 'Rule'){$Observed.Rule}else{$Observed.Filters[$kind]};$values=[ordered]@{}
        foreach($name in $fields[$kind]){
            $property=$item.PSObject.Properties[$name]
            $values[$name]=[ordered]@{Present=($null -ne $property);Value=$(if($null -eq $property -or $null -eq $property.Value){$null}else{@($property.Value|ForEach-Object {[string]$_})})}
        }
        $result[$kind]=$values
    }
    [pscustomobject]$result
}
function Assert-WelaIngressReadback {
    param($Observed,$Selection)
    $r=$Observed.Rule;$f=$Observed.Filters
    foreach($field in @('Name','DisplayName')){if([string]$r.$field -cne $Selection.Name){throw "Rule $field differs."}}
    $fixed=@{Description='WELA reviewed collector ingress; TCP 5985, Domain profile, explicit IPv4 scopes.';Group='WELA reviewed collector ingress';Enabled='True';Profile='Domain';Direction='Inbound';Action='Allow';EdgeTraversalPolicy='Block';LooseSourceMapping='False';LocalOnlyMapping='False';PolicyStoreSourceType='Local'}
    foreach($field in $fixed.Keys){if([string]$r.$field -cne $fixed[$field]){throw "Rule $field differs."}}
    if($r.Owner -or @($r.Platform|Where-Object {$_}).Count){throw 'Unexpected rule owner or platform restriction.'}
    if([string]$f.Port.Protocol -notin @('TCP','6') -or [string]$f.Port.LocalPort -ne '5985' -or [string]$f.Port.RemotePort -ne 'Any' -or [string]$f.Port.IcmpType -ne 'Any' -or [string]$f.Port.DynamicTarget -ne 'Any'){throw 'Port filter differs.'}
    $local=@($f.Address.LocalAddress|ForEach-Object {ConvertTo-WelaIngressAddress $_}|Sort-Object)
    $remote=@($f.Address.RemoteAddress|ForEach-Object {ConvertTo-WelaIngressAddress $_ -Remote -Observed}|Sort-Object)
    if(($local -join '|') -cne ($Selection.LocalAddresses -join '|') -or ($remote -join '|') -cne ($Selection.RemoteAddresses -join '|')){throw 'Address filters differ.'}
    foreach($pair in @(@('Application','Program'),@('Service','Service'),@('Interface','InterfaceAlias'),@('InterfaceType','InterfaceType'),@('Security','LocalUser'),@('Security','RemoteUser'),@('Security','RemoteMachine'))){if([string]$f[$pair[0]].($pair[1]) -ne 'Any'){throw "Unexpected $($pair -join '/') filter: '$($f[$pair[0]].($pair[1]))'."}}
    # Native Package is a nullable SID, unlike the Program 'Any' alias. A
    # present empty/null Package means no package restriction; missing is unknown.
    $package=$f.Application.PSObject.Properties['Package']
    if($null -eq $package -or ($null -ne $package.Value -and ($package.Value -isnot [string] -or $package.Value -cnotin @('','Any')))){throw 'Unexpected or missing Application/Package filter.'}
    if([string]$f.Security.Authentication -ne 'NotRequired' -or [string]$f.Security.Encryption -ne 'NotRequired' -or [string]$f.Security.OverrideBlockRules -ne 'False'){throw 'Security filter differs.'}
}
function Assert-WelaIngressPlan {
    param($Plan)
    Assert-WelaArrivalObject $Plan @('SchemaVersion','Kind','Selection','ContextKey','Sources','RecordedUtc')
    if(($Plan.SchemaVersion -isnot [int] -and $Plan.SchemaVersion -isnot [long]) -or $Plan.SchemaVersion -ne 1 -or $Plan.Kind -cne 'WelaCollectorIngressPlan' -or $Plan.ContextKey -isnot [string] -or $Plan.Sources -isnot [string]){throw 'Unknown ingress plan.'}
    Assert-WelaArrivalObject $Plan.Selection @('Name','LocalAddresses','RemoteAddresses')
    if($Plan.Selection.Name -isnot [string] -or $Plan.Selection.LocalAddresses -isnot [array] -or $Plan.Selection.RemoteAddresses -isnot [array]){throw 'Mistyped ingress selection.'}
    $null=Get-WelaIngressSelection $Plan.Selection.Name $Plan.Selection.LocalAddresses $Plan.Selection.RemoteAddresses
    $null=ConvertTo-WelaArrivalUtc $Plan.RecordedUtc
}
function Invoke-WelaWecIngress {
    param([ValidateSet('Plan','Apply')][string]$Action='Plan',[string]$Name,[string[]]$LocalAddress,[string[]]$RemoteAddress,[string]$PlanPath,[string]$PlanHash,[Parameter(Mandatory)][string]$OutputPath)
    if($Action -eq 'Plan'){
        if(-not $Name -or -not $LocalAddress -or -not $RemoteAddress -or $PlanPath -or $PlanHash){throw 'Plan requires a new rule name and explicit local/remote IPv4 scopes, without a prior plan.'}
        $selection=Get-WelaIngressSelection $Name $LocalAddress $RemoteAddress;$inputFile=$null
    }else{
        if(-not $PlanPath -or $PlanHash -cnotmatch '^[a-f0-9]{64}$' -or $Name -or $LocalAddress -or $RemoteAddress){throw 'Apply accepts only a reviewed plan path, SHA256 and new output.'}
        $inputFile=Read-WelaWecUpdateFile $PlanPath
    }
    $ErrorActionPreference='Stop'
    $sourcePath=if($inputFile){$inputFile.Path}else{Join-Path (Split-Path $PSScriptRoot -Parent) 'WELA.ps1'}
    $output=New-WelaArrivalOutput $OutputPath $sourcePath
    $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaCollectorIngress';Action=$Action;Status='Refused';ExitCode=1;OutputPath=$output;PlanHash=$null;NativeCreateAttempted=$false;Artifacts=@();Diagnostic='';ReadyRuleCredit=0;Scope='One local Domain-profile TCP5985 IPv4 allow rule only. Other rules may allow broader access; no listener, service, authentication, subscription, packet delivery or Sigma proof. Sysmon excluded.'}
    try {
        $context=Get-WelaIngressContext;$key=$context|ConvertTo-Json -Depth 16 -Compress;$sources=Get-WelaIngressSources
        if($Action -eq 'Apply'){
            if($inputFile.Hash -cne $PlanHash){throw 'Reviewed plan hash differs.'}
            $plan=ConvertFrom-WelaArrivalJson $inputFile.Text;Assert-WelaIngressPlan $plan
            if($plan.ContextKey -cne $key -or $plan.Sources -cne $sources){throw 'Host, reader, firewall context or source code differs from reviewed plan.'}
            $selection=Get-WelaIngressSelection $plan.Selection.Name $plan.Selection.LocalAddresses $plan.Selection.RemoteAddresses;$report.PlanHash=$inputFile.Hash
        }
        foreach($address in $selection.LocalAddresses){if($address -cnotin $context.Addresses){throw 'Every local address must currently be assigned and Preferred.'}}
        Assert-WelaIngressAbsent $selection.Name
        if($Action -eq 'Plan'){
            $plan=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaCollectorIngressPlan';Selection=$selection;ContextKey=$key;Sources=$sources;RecordedUtc=[DateTime]::UtcNow.ToString('o')};Assert-WelaIngressPlan $plan
            if((Get-WelaIngressContext|ConvertTo-Json -Depth 16 -Compress) -cne $key -or (Get-WelaIngressSources) -cne $sources){throw 'Context or code drift during planning.'}
            Assert-WelaIngressAbsent $selection.Name
            $artifact=Write-WelaWecUpdateArtifact $output 'plan.json' ($plan|ConvertTo-Json -Depth 20);$report.Artifacts+=$artifact;$report.PlanHash=$artifact.Sha256;$report.Status='ReviewRequired';$report.ExitCode=0
        }else{
            $report.Artifacts+=Write-WelaWecUpdateArtifact $output 'reviewed-plan.json' $inputFile.Text
            $report.Artifacts+=Write-WelaWecUpdateArtifact $output 'before-create.json' ([ordered]@{Status='Pending';Selection=$selection;Context=$context;PlanHash=$PlanHash;RecordedUtc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Depth 20)
            if((Read-WelaWecUpdateFile $PlanPath).Hash -cne $PlanHash -or (Get-WelaIngressSources) -cne $sources -or (Get-WelaIngressContext|ConvertTo-Json -Depth 16 -Compress) -cne $key){throw 'Plan, context or source drift immediately before creation.'}
            Assert-WelaIngressAbsent $selection.Name
            $report.NativeCreateAttempted=$true;New-WelaIngressNativeRule $selection
            foreach($store in @('PersistentStore','ActiveStore')){
                $observed=Read-WelaIngressRule $store $selection.Name
                $report.Artifacts+=Write-WelaWecUpdateArtifact $output ($store+'-after.json') ((ConvertTo-WelaIngressEvidence $observed)|ConvertTo-Json -Depth 8)
                Assert-WelaIngressReadback $observed $selection
            }
            if((Read-WelaWecUpdateFile $PlanPath).Hash -cne $PlanHash -or (Get-WelaIngressSources) -cne $sources -or (Get-WelaIngressContext|ConvertTo-Json -Depth 16 -Compress) -cne $key){throw 'Context, code or plan changed after creation.'}
            $report.Status='CreatedAndVerified';$report.ExitCode=0
        }
    }catch{$report.Status=if($report.NativeCreateAttempted){'CreateAttemptedUnverified'}else{'Refused'};$report.Diagnostic=$_.Exception.Message}
    $null=Write-WelaWecUpdateArtifact $output 'manifest.json' ($report|ConvertTo-Json -Depth 20)
    $report
}
