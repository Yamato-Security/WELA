# Reviewed authorization only; an enabled subscription is never edited or paused.
function Get-WelaWecAuthorizationKey {param($Value) ConvertTo-Json -InputObject $Value -Depth 24 -Compress}
function Get-WelaWecAuthorizationSids {
    param([object[]]$SourceSids)
    if($SourceSids.Count -lt 1 -or $SourceSids.Count -gt 32){throw 'Select 1 to 32 explicit domain-format source SIDs.'}
    $seen=@{};$result=@()
    foreach($sid in $SourceSids){
        if($sid -isnot [string] -or $sid -cnotmatch '^S-1-5-21-(0|[1-9][0-9]{0,9})-(0|[1-9][0-9]{0,9})-(0|[1-9][0-9]{0,9})-(0|[1-9][0-9]{0,9})$'){throw 'Source SIDs must be canonical explicit domain-format strings.'}
        foreach($part in @($sid.Split('-')|Select-Object -Skip 4)){$value=[uint32]0;if(-not [uint32]::TryParse($part,[ref]$value)){throw 'Source SID subauthority exceeds the native range.'}}
        if($seen.ContainsKey($sid)){throw 'Duplicate source SID.'};$seen[$sid]=$true;$result+=$sid
    }
    [string[]]$ordered=$result;[Array]::Sort($ordered,[StringComparer]::Ordinal);$ordered
}
function Get-WelaWecAuthorizationDefinition {
    param([string]$Xml)
    if(-not $Xml -or $Xml.Length -gt 1048576){throw 'Native subscription XML is absent or oversized.'}
    $doc=Read-WelaWefXml $Xml;$root=$doc.DocumentElement;$ns=[Xml.XmlNamespaceManager]::new($doc.NameTable);$ns.AddNamespace('s','http://schemas.microsoft.com/2006/03/windows/events/subscription')
    $nodes=@($root.SelectNodes('s:AllowedSourceDomainComputers',$ns));if($nodes.Count -ne 1){throw 'One explicit source authorization is required.'}
    $authorization=[string]$nodes[0].InnerText
    if($authorization.Length -gt 4096 -or $authorization -cnotmatch '^O:NSG:NSD:(?:\(A;;GA;;;S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+\)){1,32}$'){throw 'Only the explicit standard domain-source allow list is supported; no arbitrary/default SDDL.'}
    $sids=@(Get-WelaWecAuthorizationSids @([regex]::Matches($authorization,'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+')|ForEach-Object Value))
    if((Get-WelaWefAuthorization $sids) -cne $authorization){throw 'Observed authorization is not the canonical explicit SID list.'}
    $model=ConvertFrom-WelaWefSubscription -Xml $Xml -SourceSids $sids -Observed
    if($model.Definition.Enabled -ne $false){throw 'Only an already disabled source-initiated subscription can change authorization.'}
    $whole=Get-WelaWefXmlKey $root;$null=$root.RemoveChild($nodes[0])
    [pscustomobject][ordered]@{Id=$model.Id;Xml=$Xml;SourceSids=$sids;Authorization=$authorization;WholeKey=$whole;PreservedKey=(Get-WelaWefXmlKey $root);QueryKey=$model.Query.Key;Description=$model.Definition.Description}
}
function Read-WelaWecAuthorizationDefinition {
    param([string]$Id)
    if($Id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}$'){throw 'Select one exact subscription ID.'}
    $definition=Get-WelaWecAuthorizationDefinition (Read-WelaWecSubscriptionXml $Id)
    if($definition.Id -cne $Id){throw 'Native subscription identity differs.'};$definition
}
function Get-WelaWecAuthorizationContext {
    $reader=Get-WelaChannelReader
    if(-not $reader.ElevatedAdministrator){throw 'Actual non-impersonated elevated administrator required.'}
    $required=@(Get-Service -Name Wecsvc,Winmgmt,EventLog -ErrorAction Stop)
    if($required.Count -ne 3 -or @($required|Where-Object Status -ne Running).Count){throw 'Wecsvc, Winmgmt and EventLog must already be running; no services are started.'}
    $hostState=Get-WelaChannelReadHost
    if($hostState.ProductType -ne 3 -or $hostState.DomainRole -notin @(2,3) -or $hostState.Build -notin @(20348,26100) -or $null -eq $hostState.UBR -or $hostState.UBR -lt 1){throw 'Observed patched Server 2022/2025 member or standalone collector required.'}
    $services=@(Get-CimInstance Win32_Service -Filter "Name='Wecsvc' OR Name='Winmgmt' OR Name='EventLog'" -ErrorAction Stop|Sort-Object Name|Select-Object Name,State,StartMode)
    if($services.Count -ne 3 -or @($services|Where-Object {$_.State -ne 'Running' -or $_.StartMode -notin @('Auto','Manual')}).Count){throw 'Stable running service observations required.'}
    $log=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new('ForwardedEvents')
    try{$channel=[pscustomobject][ordered]@{Name=$log.LogName;Enabled=$log.IsEnabled;Mode=[string]$log.LogMode;MaximumBytes=$log.MaximumSizeInBytes;Path=$log.LogFilePath;SecurityDescriptor=$log.SecurityDescriptor}}finally{$log.Dispose()}
    if((Get-WelaWecAuthorizationKey (Get-WelaChannelReader)) -cne (Get-WelaWecAuthorizationKey $reader)){throw 'Actual token changed during observations.'}
    [pscustomobject][ordered]@{Host=$hostState;Reader=$reader;Services=$services;Destination=$channel}
}
function Get-WelaWecAuthorizationReviewKey {
    param($Context)
    $copy=Get-WelaWecAuthorizationKey $Context|ConvertFrom-Json
    $copy.Reader.ProcessId=$null;$copy.Reader.TokenId=$null;$copy.Reader.ModifiedId=$null
    Get-WelaWecAuthorizationKey $copy
}
function Get-WelaWecAuthorizationSources {
    $sources=[ordered]@{}
    foreach($path in @('WELA.ps1','scripts/WecAuthorization.ps1','scripts/WecAuthorizationNative.cs','scripts/ChannelRead.ps1','scripts/ChannelReadNative.cs','scripts/WefArrival.ps1','scripts/WecUpdate.ps1','modules/WefSubscriptions.psm1','modules/WecSubscriptionXml.cs','modules/AuditProfiles.psm1','scripts/CustomAuditProfiles.ps1')){$sources[$path]=(Get-FileHash -LiteralPath (Join-Path $script:ScriptRoot $path) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()}
    Get-WelaWecAuthorizationKey $sources
}
function Initialize-WelaWecAuthorizationNative {
    $bytes=[IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'WecAuthorizationNative.cs'));if($bytes.Length -gt 65536){throw 'Native authorization source exceeds bound.'}
    $hash=Get-WelaArrivalHash $bytes
    if(-not ('Wela.WecAuthorization.Edit' -as [type])){
        $source=[Text.UTF8Encoding]::new($false,$true).GetString($bytes).TrimStart([char]0xfeff)
        if([regex]::Matches($source,'__WELA_SOURCE_SHA256__').Count -ne 1){throw 'Native source binding marker is missing or ambiguous.'}
        Add-Type -TypeDefinition $source.Replace('__WELA_SOURCE_SHA256__',$hash) -ErrorAction Stop
    }
    if([Wela.WecAuthorization.Edit]::SourceSha256 -cne $hash){throw 'Loaded authorization setter differs from source; start a fresh process.'}
}
function New-WelaWecAuthorizationEdit {
    param($Before)
    Initialize-WelaWecAuthorizationNative;$edit=[Wela.WecAuthorization.Edit]::new($Before.Id)
    try{if($edit.OriginalAuthorization -cne $Before.Authorization -or $edit.OriginalDescription -cne $Before.Description -or (ConvertFrom-WelaWefQuery $edit.OriginalQuery).Key -cne $Before.QueryKey){throw 'Native handle differs from reviewed subscription.'};$edit}catch{$edit.Dispose();throw}
}
function Assert-WelaWecAuthorizationPlan {
    param($Plan)
    Assert-WelaArrivalObject $Plan @('SchemaVersion','Kind','Id','DesiredSourceSids','ContextKey','Sources','BeforeXml','RecordedUtc')
    if(($Plan.SchemaVersion -isnot [int] -and $Plan.SchemaVersion -isnot [long]) -or $Plan.SchemaVersion -ne 1 -or $Plan.Kind -isnot [string] -or $Plan.Kind -cne 'WelaWecAuthorizationPlan' -or $Plan.Id -isnot [string] -or $Plan.Id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}$' -or $Plan.DesiredSourceSids -isnot [array] -or $Plan.ContextKey -isnot [string] -or -not $Plan.ContextKey -or $Plan.Sources -isnot [string] -or -not $Plan.Sources -or $Plan.BeforeXml -isnot [string]){throw 'Unknown or mistyped authorization plan.'}
    $desired=@(Get-WelaWecAuthorizationSids $Plan.DesiredSourceSids)
    if((Get-WelaWecAuthorizationKey $desired) -cne (Get-WelaWecAuthorizationKey $Plan.DesiredSourceSids)){throw 'Desired SID list is not canonical.'}
    $null=ConvertTo-WelaArrivalUtc $Plan.RecordedUtc
    $before=Get-WelaWecAuthorizationDefinition $Plan.BeforeXml;if($before.Id -cne $Plan.Id){throw 'Plan identity contradicts original subscription.'}
}
function Assert-WelaWecAuthorizationArtifacts {
    param([string]$Output,$Artifacts)
    foreach($a in $Artifacts){if((Get-FileHash -LiteralPath (Join-Path $Output $a.Name) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() -cne $a.Sha256){throw 'Retained authorization evidence changed.'}}
}
function Invoke-WelaWecAuthorization {
    param([ValidateSet('Plan','Apply')][string]$Action='Plan',[string]$Id,[object[]]$SourceSids,[string]$PlanPath,[string]$PlanHash,[string]$OutputPath)
    $ErrorActionPreference='Stop'
    if($args.Count){throw 'Unknown authorization arguments are not supported.'}
    if($Action -eq 'Plan'){
        if(-not $Id -or -not $SourceSids -or -not $OutputPath -or $PSBoundParameters.ContainsKey('PlanPath') -or $PSBoundParameters.ContainsKey('PlanHash')){throw 'Plan requires exact ID, desired source SIDs and new output only.'}
        $desired=@(Get-WelaWecAuthorizationSids $SourceSids);$reviewed=$null;$source=Join-Path $script:ScriptRoot 'scripts'
    }else{
        if(-not $PlanPath -or $PlanHash -cnotmatch '^[a-fA-F0-9]{64}$' -or -not $OutputPath -or $PSBoundParameters.ContainsKey('Id') -or $PSBoundParameters.ContainsKey('SourceSids')){throw 'Apply accepts only a reviewed plan, SHA256 and new output.'}
        $PlanHash=$PlanHash.ToLowerInvariant();$reviewed=Read-WelaWecUpdateFile $PlanPath;$source=$reviewed.Path
    }
    $output=New-WelaArrivalOutput $OutputPath $source
    $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaWecAuthorization';Action=$Action;Status='Refused';ExitCode=1;OutputPath=$output;PlanHash=$null;NativeSaveAttempted=$false;NativeErrorCode=$null;BeforeSourceSids=@();DesiredSourceSids=@();After=$null;Artifacts=@();Diagnostic='';ReadyRuleCredit=0;Scope='Only the explicit source-domain SID authorization of one existing disabled native subscription. No SID resolution, AD membership, authentication, forwarding, bookmark or Sigma proof; Sysmon excluded.'}
    $edit=$null;$plan=$null
    try {
        $context=Get-WelaWecAuthorizationContext;$contextKey=Get-WelaWecAuthorizationKey $context;$sources=Get-WelaWecAuthorizationSources
        if($Action -eq 'Plan'){
            $before=Read-WelaWecAuthorizationDefinition $Id
            $plan=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaWecAuthorizationPlan';Id=$Id;DesiredSourceSids=$desired;ContextKey=(Get-WelaWecAuthorizationReviewKey $context);Sources=$sources;BeforeXml=$before.Xml;RecordedUtc=[DateTime]::UtcNow.ToString('o')}
            Assert-WelaWecAuthorizationPlan $plan
            if((Read-WelaWecAuthorizationDefinition $Id).WholeKey -cne $before.WholeKey -or (Get-WelaWecAuthorizationKey (Get-WelaWecAuthorizationContext)) -cne $contextKey -or (Get-WelaWecAuthorizationSources) -cne $sources){throw 'Context, subscription or sources changed during planning.'}
            $text=$plan|ConvertTo-Json -Depth 24;if([Text.Encoding]::UTF8.GetByteCount($text) -gt 4194304){throw 'Reviewed plan exceeds four MiB.'}
            $artifact=Write-WelaWecUpdateArtifact $output 'plan.json' $text;$report.Artifacts+=$artifact;$report.PlanHash=$artifact.Sha256;$report.Status='ReviewRequired'
        }else{
            if($reviewed.Hash -cne $PlanHash){throw 'Reviewed plan hash differs.'};$plan=ConvertFrom-WelaArrivalJson $reviewed.Text;Assert-WelaWecAuthorizationPlan $plan;$report.PlanHash=$PlanHash
            if($plan.ContextKey -cne (Get-WelaWecAuthorizationReviewKey $context) -or $plan.Sources -cne $sources){throw 'Reviewed actual host/operator/service/channel or sources differ.'}
            $before=Get-WelaWecAuthorizationDefinition $plan.BeforeXml;$desired=@($plan.DesiredSourceSids);$desiredAuthorization=Get-WelaWefAuthorization $desired
            if((Read-WelaWecAuthorizationDefinition $plan.Id).WholeKey -cne $before.WholeKey){throw 'Current subscription differs from reviewed complete definition.'}
            $report.Artifacts+=Write-WelaWecUpdateArtifact $output 'reviewed-plan.json' $reviewed.Text
            if($before.Authorization -ceq $desiredAuthorization){$report.Status='AlreadyMatches'}else{
                $edit=New-WelaWecAuthorizationEdit $before
                $report.Artifacts+=Write-WelaWecUpdateArtifact $output 'before-save.json' ([ordered]@{Status='Pending';PlanHash=$PlanHash;Context=$context;BeforeXml=$before.Xml;DesiredSourceSids=$desired;DesiredAuthorization=$desiredAuthorization;RecordedUtc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Depth 24)
                Assert-WelaWecAuthorizationArtifacts $output $report.Artifacts
                if((Read-WelaWecUpdateFile $PlanPath).Hash -cne $PlanHash -or (Get-WelaWecAuthorizationSources) -cne $sources -or (Get-WelaWecAuthorizationKey (Get-WelaWecAuthorizationContext)) -cne $contextKey -or (Read-WelaWecAuthorizationDefinition $plan.Id).WholeKey -cne $before.WholeKey){throw 'Plan, code, context or complete subscription changed immediately before save.'}
                try{$edit.Save($desiredAuthorization)}finally{$report.NativeSaveAttempted=[bool]$edit.SaveAttempted}
            }
            $after=Read-WelaWecAuthorizationDefinition $plan.Id;$report.After=$after;$report.Artifacts+=Write-WelaWecUpdateArtifact $output 'after.xml' $after.Xml
            if($after.Authorization -cne $desiredAuthorization -or $after.PreservedKey -cne $before.PreservedKey -or (Get-WelaWecAuthorizationKey (Get-WelaWecAuthorizationContext)) -cne $contextKey -or (Get-WelaWecAuthorizationSources) -cne $sources -or (Read-WelaWecUpdateFile $PlanPath).Hash -cne $PlanHash){throw 'Authorization readback, preserved definition, context, source or plan differs after operation.'}
            if($report.NativeSaveAttempted){$report.Status='AuthorizationChangedAndVerified'}
        }
        $report.BeforeSourceSids=@($before.SourceSids);$report.DesiredSourceSids=@($plan.DesiredSourceSids)
        Assert-WelaWecAuthorizationArtifacts $output $report.Artifacts;$report.ExitCode=0
    }catch{
        $report.Status=if($report.NativeSaveAttempted){'SaveAttemptedUnverified'}else{'Refused'};$report.ExitCode=1;$report.Diagnostic=$_.Exception.Message
        $exception=$_.Exception;while($exception){if($exception -is [ComponentModel.Win32Exception]){$report.NativeErrorCode=$exception.NativeErrorCode;break};$exception=$exception.InnerException}
        if($report.NativeSaveAttempted -and $plan){try{$xml=Read-WelaWecSubscriptionXml $plan.Id;$report.Artifacts+=Write-WelaWecUpdateArtifact $output 'failed-after.xml' $xml}catch{$report.Diagnostic+=' Final native definition unavailable: '+$_.Exception.Message}}
    }finally{if($edit){try{$edit.Dispose()}catch{$report.ExitCode=1;$report.Status=if($report.NativeSaveAttempted){'SaveAttemptedUnverified'}else{'Refused'};$report.Diagnostic+=' Native handle cleanup failed: '+$_.Exception.Message}}}
    $null=Write-WelaWecUpdateArtifact $output 'manifest.json' ($report|ConvertTo-Json -Depth 24);$report
}
