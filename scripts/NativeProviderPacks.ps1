# Opt-in native provider/channel inventory. No rule evaluation or implied readiness.
function Get-WelaProviderPackCatalog {
    $base = Join-Path $PSScriptRoot '../config'
    $catalog = Get-Content -LiteralPath (Join-Path $base 'native_provider_packs.json') -Raw -ErrorAction Stop | ConvertFrom-Json
    if ($catalog.schemaVersion -ne 1 -or $catalog.id -ne 'native-provider-packs-v1') { throw 'Unsupported provider pack catalog.' }
    $hash = (Get-FileHash -LiteralPath (Join-Path $base 'security_rules.json') -Algorithm SHA256).Hash
    if ($hash -ne $catalog.corpusSha256) { throw 'Provider pack corpus pin mismatch; review the updated corpus before using these packs.' }
    $parsed = Get-Content -LiteralPath (Join-Path $base 'security_rules.json') -Raw | ConvertFrom-Json
    $ids = @{}; foreach ($rule in @($parsed)) { $ids[$rule.id] = $true }
    $reviews = @{}
    foreach ($review in $catalog.ruleReviews) {
        if (-not $ids.ContainsKey($review.id) -or $reviews.ContainsKey($review.id) -or
            $review.id -notmatch '^[a-fA-F0-9-]{36}$' -or $review.localPath -cne ('provider_rule_sources/' + $review.id + '.yml')) { throw 'Invalid provider rule review identity/path.' }
        if ((Get-FileHash -LiteralPath (Join-Path $base $review.localPath) -Algorithm SHA256).Hash -ne $review.sha256) { throw "Pinned full rule changed: $($review.id)" }
        $reviews[$review.id] = $true
    }
    $names = @{}
    foreach ($pack in $catalog.packs) {
        if (-not $pack.id -or $names.ContainsKey($pack.id) -or $pack.mode -notin @('Configure','ManualOnly') -or
            -not $pack.provider -or -not $pack.channel -or $pack.channel -match '[*?\[\]\r\n]' -or $pack.provider -match '[*?\[\]\r\n]' -or
            $pack.events.Count -eq 0 -or $pack.minimumBytes -lt 1048576) { throw 'Invalid provider pack definition.' }
        $names[$pack.id] = $true
        foreach ($id in $pack.ruleIds) { if (-not $reviews.ContainsKey($id)) { throw "Full rule review missing: $id" } }
    }
    return $catalog
}

function Get-WelaProviderTemplateFields {
    param([string]$Template)
    if (-not $Template) { return }
    $settings = New-Object Xml.XmlReaderSettings
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit; $settings.XmlResolver = $null; $settings.MaxCharactersInDocument = 1048576
    $reader = [Xml.XmlReader]::Create([IO.StringReader]::new($Template), $settings)
    try { $xml = New-Object Xml.XmlDocument; $xml.XmlResolver=$null; $xml.Load($reader) } finally { $reader.Dispose() }
    $seen = @{}
    foreach ($field in $xml.SelectNodes('//*[local-name()="data"]')) {
        $name = $field.GetAttribute('name')
        if (-not $name -or $seen.ContainsKey($name)) { throw 'Template contains missing or duplicate field names.' }
        $seen[$name]=$true
        [pscustomobject]@{ Name=$name; InType=$field.GetAttribute('inType'); OutType=$field.GetAttribute('outType') }
    }
}

function Get-WelaProviderPackSchema {
    param($Pack)
    $provider = $null; $providers=@(); $logs=@()
    try {
        $logs = @(Get-WinEvent -ListLog $Pack.channel -ErrorAction Stop | Where-Object LogName -eq $Pack.channel)
        if ($logs.Count -ne 1) { throw 'Exact channel registration was not returned.' }
        $providers = @(Get-WinEvent -ListProvider $Pack.provider -ErrorAction Stop | Where-Object Name -eq $Pack.provider)
        if ($providers.Count -ne 1) { throw 'Exact provider registration was not returned.' }
        $provider=$providers[0]
        if ([guid]$provider.Id -eq [guid]::Empty) { throw 'Provider GUID is unknown.' }
        if (@($logs[0].ProviderNames) -notcontains $Pack.provider -or @($provider.LogLinks.LogName) -notcontains $Pack.channel) { throw 'Provider/channel links disagree.' }
        $events = @()
        foreach ($event in $provider.Events) {
            if (@($Pack.events.id) -contains [int]$event.Id -and $event.LogLink.LogName -eq $Pack.channel) {
                $fields = @(Get-WelaProviderTemplateFields -Template $event.Template)
                $sha = [Security.Cryptography.SHA256]::Create()
                try { $templateHash = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$event.Template)))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
                $events += [pscustomobject]@{ Id=[int]$event.Id; Version=[int]$event.Version; Channel=[string]$event.LogLink.LogName; Fields=$fields; TemplateSha256=$templateHash }
            }
        }
        [pscustomobject]@{ State='Observed'; Provider=[string]$provider.Name; ProviderGuid=[string]$provider.Id; ChannelType=[string]$logs[0].LogType; Events=$events; Diagnostic=$null }
    } catch { [pscustomobject]@{ State='Unknown'; Provider=$Pack.provider; ProviderGuid=$null; ChannelType=$null; Events=@(); Diagnostic=$_.Exception.Message } }
    finally { foreach ($metadata in @($providers) + @($logs)) { if ($metadata -is [IDisposable]) { $metadata.Dispose() } } }
}

function Get-WelaProviderPackObservation {
    param($Pack, $Catalog)
    $reasons = New-Object 'System.Collections.Generic.List[string]'
    $hostContext=$null; $service=$null
    try {
        $hostContext=Get-WelaHostContext
        $family=if ($hostContext.Role -eq 'Client') {'Client'} else {'Server'}
        if ($Pack.roles -notcontains $hostContext.Role -or $Catalog.buildFamilies.$family -notcontains $hostContext.Build) { $reasons.Add('Role/build outside reviewed families; no configuration allowed.') }
    } catch { $reasons.Add("Role/build unknown: $_") }
    if ($Pack.requiredService) {
        $service=Get-WelaNativeService -Name $Pack.requiredService
        if ($service.State -notin @('Running','Stopped','Paused','StartPending','StopPending','ContinuePending','PausePending')) { $reasons.Add('Required DNS Server service is absent or unreadable; a DC role alone does not prove DNS is installed.') }
    }
    $schema=Get-WelaProviderPackSchema -Pack $Pack
    if ($schema.State -ne 'Observed') { $reasons.Add("Provider schema unknown: $($schema.Diagnostic)") }
    if ($schema.ChannelType -notin @('Administrative','Operational')) { $reasons.Add('Only observed Administrative/Operational channels can be configured; Analytical/Debug channels remain manual.') }
    foreach ($expected in $Pack.events) {
        $events=@($schema.Events | Where-Object Id -eq $expected.id)
        if ($events.Count -eq 0) { $reasons.Add("Expected event $($expected.id) is absent from the exact provider/channel manifest."); continue }
        foreach ($event in $events) {
            foreach ($name in $expected.requiredFields) {
                $fields=@($event.Fields | Where-Object Name -ceq $name)
                if ($fields.Count -ne 1 -or $fields[0].InType -notin @('win:UnicodeString','win:AnsiString')) { $reasons.Add("Event $($event.Id) version $($event.Version) lacks the required string field $name.") }
            }
        }
    }
    if ($Pack.mode -ne 'Configure') { $reasons.Add('Inventory/manual review only; this pack never enables its channel.') }
    # Within-run manifest identity, not cross-host rule identity or detection proof.
    $fingerprint=@($hostContext.Role,$hostContext.Build,$schema.Provider,$schema.ProviderGuid,$schema.ChannelType,$service.State)
    foreach ($event in @($schema.Events | Sort-Object Id,Version)) { $fingerprint += "$($event.Id)/$($event.Version)/$($event.TemplateSha256)" }
    [pscustomobject]@{ CanConfigure=($reasons.Count -eq 0); Reasons=@($reasons.ToArray()); HostContext=$hostContext; Service=$service; Schema=$schema; Fingerprint=($fingerprint -join '|') }
}

function Get-WelaProviderPackPlan {
    param($Catalog, [string[]]$Names)
    if (-not $Names -or $Names.Count -eq 0) { throw 'Select one or more explicit -ProviderPack names; no default pack is applied.' }
    $selected=@{}
    foreach ($name in $Names) {
        if ($selected.ContainsKey($name)) { throw "Duplicate provider pack: $name" }; $selected[$name]=$true
        if (@($Catalog.packs | Where-Object id -eq $name).Count -ne 1) { throw "Unknown provider pack: $name" }
    }
    foreach ($name in $Names) {
        $pack=@($Catalog.packs | Where-Object id -eq $name)[0]
        $observation=Get-WelaProviderPackObservation -Pack $pack -Catalog $Catalog
        if ($pack.id -eq 'capi2') { $control=@((Get-WelaNativeChannelProfile).controls | Where-Object channel -eq $pack.channel)[0] }
        else { $control=[pscustomobject]@{ channel=$pack.channel; enabled=$true; sourceExampleBytes=[long]$pack.minimumBytes; readerSid=$null; readerMask=$null } }
        if (-not $control) { throw 'CAPI2 shared channel control is missing.' }
        $plan=@(Get-WelaNativeChannelPlan -Profile ([pscustomobject]@{controls=@($control)}))[0]
        $plan | Add-Member NoteProperty Pack $pack
        $plan | Add-Member NoteProperty Catalog $Catalog
        $plan | Add-Member NoteProperty ProviderEvidence $observation
        $plan | Add-Member NoteProperty PrerequisiteDiagnostic ($observation.Reasons -join ' ')
        $reviews=@($Catalog.ruleReviews | Where-Object { $pack.ruleIds -contains $_.id } | ForEach-Object {
            [pscustomobject]@{ Id=$_.id; Title=$_.title; Source=($Catalog.ruleRepository+'/blob/'+$Catalog.ruleCommit+'/'+$_.path); SourceSha256=$_.sha256; DefinitionPath=$_.localPath; RuleChannels=$_.ruleChannels; ObservedTargetChannel=$pack.channel; ChannelMismatch=(@($_.ruleChannels | Where-Object { $_ -cne $pack.channel }).Count -gt 0); RequiredEventFields=$_.requiredEventFields; Operators=$_.operators; Condition=$_.condition; Eligibility='Conditional'; Reason='Full native event, backend field mapping/translation and repeatable matching evidence remain unverified.' }
        })
        $plan | Add-Member NoteProperty RuleReviews $reviews
        if (-not $observation.CanConfigure) { $plan.Status='ManualReview' }
        $plan
    }
}

function Invoke-WelaProviderPackCommand {
    param([ValidateSet('List','Audit','Plan','Configure')][string]$Action='List', [string[]]$Names,
        [switch]$Auto, [switch]$DryRun, [string]$BackupPath, [string]$ResultsPath)
    if ($DryRun -and $Action -ne 'Configure') { throw '-DryRun requires ProviderAction Configure.' }
    $catalog=Get-WelaProviderPackCatalog
    if ($Action -eq 'List') {
        if ($Names) { throw 'List inventories all packs; select -ProviderPack with Audit, Plan or Configure.' }
        $report=[pscustomobject]@{ Scope='native-provider-pack-inventory'; ExitCode=0; Catalog=$catalog; ReadyRules=0; Evidence='Definitions only; no host observations or event/backend evidence.' }
        if ($ResultsPath) { $report | ConvertTo-Json -Depth 24 | Set-Content -LiteralPath $ResultsPath -Encoding UTF8 -ErrorAction Stop }
        return $report
    }
    if ($env:OS -ne 'Windows_NT') { throw 'Provider pack observations/configuration require Windows.' }
    $plan=@(Get-WelaProviderPackPlan -Catalog $catalog -Names $Names)
    if ($Action -eq 'Configure') {
        $context=New-WelaConfigurationContext -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath
        $guard={ param($entry)
            $fresh=Get-WelaProviderPackObservation -Pack $entry.Pack -Catalog $entry.Catalog
            if (-not $fresh.CanConfigure -or $fresh.Fingerprint -cne $entry.ProviderEvidence.Fingerprint) { throw 'Provider role/service/channel type or event schema changed or became unknown; no channel write allowed.' }
        }
        Set-WelaNativeChannelControls -Context $context -Plan $plan -Profile $catalog.id -ValidatePrerequisites $guard
        $report=Complete-WelaConfiguration -Context $context -Scope 'native-channel-settings-only' -SuccessMessage 'Requested provider channel settings verified. Event generation, identity access and backend detection remain unverified.'
    } else { $report=[pscustomobject]@{ Scope='native-provider-pack-inventory'; ExitCode=$(if (@($plan | Where-Object Status -in @('Unknown','NotInstalled','ManualReview')).Count) {1} else {0}) } }
    # Configuration results contain verified after-state; Controls retain the reviewed
    # pre-write plan explicitly, never masquerading as current observation.
    $report | Add-Member NoteProperty Action $Action
    $report | Add-Member NoteProperty ControlsPlan @($plan | Select-Object Definition,Before,Status,Access,Desired,Prerequisites,Pack,ProviderEvidence,RuleReviews)
    $report | Add-Member NoteProperty CorpusSha256 $catalog.corpusSha256
    $report | Add-Member NoteProperty RuleCommit $catalog.ruleCommit
    $report | Add-Member NoteProperty ReadyRules 0
    $report | Add-Member NoteProperty UnverifiedEvidence @('Effective event-reader identity access','Representative emitted event XML and required field values','Backend translation, ingestion and matching result','Generic-category adapters and event volume')
    if ($ResultsPath) { try { $report | ConvertTo-Json -Depth 24 | Set-Content -LiteralPath $ResultsPath -Encoding UTF8 -ErrorAction Stop } catch { $report.ExitCode=1; Write-Warning "Provider report export failed: $_" } }
    return $report
}
