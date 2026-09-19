# Reviewed, existing-only updates of disabled source-initiated subscriptions.
function Write-WelaWecUpdateArtifact {
    param([string]$Root,[string]$Name,[string]$Text)
    $null=Resolve-WelaArrivalPath $Root
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($Text);$path=Join-Path $Root $Name
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try {$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true);$stream.Position=0;$sha=[Security.Cryptography.SHA256]::Create();try{$readback=([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}}finally{$stream.Dispose()}
    $hash=Get-WelaArrivalHash $bytes
    if($readback -cne $hash){throw 'Update artifact readback differs.'}
    [pscustomobject]@{Name=$Name;Sha256=$hash;Bytes=$bytes.Length}
}
function Get-WelaWecUpdateContext {
    if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess){throw '64-bit native Windows is required.'}
    $hostState=Get-WelaDefaultContext
    if(-not(Test-WelaDefaultContextComplete $hostState) -or $hostState.ProductType -ne 3 -or $hostState.Build -notin @(20348,26100) -or $hostState.DomainRole -notin @(2,3)){throw 'An observed Server 2022/2025 member or standalone collector is required.'}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try{$reader=[ordered]@{Name=$identity.Name;Sid=$identity.User.Value;Groups=@($identity.Groups.Value|Sort-Object)}}finally{$identity.Dispose()}
    $service=Get-CimInstance Win32_Service -Filter "Name='Wecsvc'" -ErrorAction Stop
    if(-not $service -or $service.State -ne 'Running'){throw 'Wecsvc must already be running; no service changes are made.'}
    [pscustomobject][ordered]@{Computer=[Environment]::MachineName;HostKey=(Get-WelaDefaultContextKey $hostState);Reader=$reader;Service=[ordered]@{State=[string]$service.State;StartMode=[string]$service.StartMode}}
}
function Get-WelaWecUpdateSources {
    $root=Split-Path $PSScriptRoot -Parent
    $sources=[ordered]@{}
    foreach($name in @('scripts/WecUpdate.ps1','scripts/WecUpdateNative.cs','modules/WefSubscriptions.psm1','modules/WecSubscriptionXml.cs','scripts/Configuration.ps1','scripts/ControlApplicability.ps1','scripts/WefArrival.ps1','modules/AuditProfiles.psm1')){$sources[$name]=(Get-FileHash -LiteralPath (Join-Path $root $name) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()}
    $sources|ConvertTo-Json -Compress
}
function Read-WelaWecUpdateFile {
    param([string]$Path,[int]$MaximumBytes=4194304)
    $full=Resolve-WelaArrivalPath $Path;$stream=[IO.File]::Open($full,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if($stream.Length -gt $MaximumBytes){throw 'Update input exceeds its size limit.'}
        $bytes=New-Object byte[] ([int]$stream.Length);$offset=0
        while($offset -lt $bytes.Length){$read=$stream.Read($bytes,$offset,$bytes.Length-$offset);if($read -eq 0){throw 'Update input was truncated.'};$offset+=$read}
        $text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes).TrimStart([char]0xFEFF)
        [pscustomobject]@{Path=$full;Text=$text;Hash=(Get-WelaArrivalHash $bytes)}
    }finally{$stream.Dispose()}
}
function Get-WelaWecUpdateDefinition {
    param([string]$Xml,[string[]]$SourceSids)
    $model=ConvertFrom-WelaWefSubscription -Xml $Xml -SourceSids $SourceSids -Observed
    if($model.Definition.Enabled -ne $false){throw 'Only an already disabled subscription can be updated; no activation or pause is performed.'}
    $doc=Read-WelaWefXml $Xml;$root=$doc.DocumentElement;$whole=Get-WelaWefXmlKey $root
    $ns=New-Object Xml.XmlNamespaceManager($doc.NameTable);$ns.AddNamespace('s',$root.NamespaceURI)
    $query=$root.SelectSingleNode('s:Query',$ns).InnerText
    $description=$root.SelectSingleNode('s:Description',$ns);$descriptionText=if($description){[string]$description.InnerText}else{''}
    foreach($node in @($root.SelectNodes('s:Query|s:Description',$ns))){$null=$root.RemoveChild($node)}
    [pscustomobject]@{Id=$model.Id;Xml=$Xml;WholeKey=$whole;PreservedKey=(Get-WelaWefXmlKey $root);QueryXml=$query;QueryKey=$model.Query.Key;Description=$descriptionText}
}
function Read-WelaWecUpdateDefinition {
    param([string]$Id,[string[]]$SourceSids)
    if($Id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}$'){throw 'Invalid exact subscription ID.'}
    $definition=Get-WelaWecUpdateDefinition (Read-WelaWecSubscriptionXml $Id) $SourceSids
    if($definition.Id -cne $Id){throw 'Native subscription identity differs from the selected ID.'}
    $definition
}
function New-WelaWecUpdateEdit {
    param($Before)
    $path=Join-Path $PSScriptRoot 'WecUpdateNative.cs';$hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
    if(-not('Wela.WecUpdate.Edit' -as [type])){Add-Type -Path $path -ErrorAction Stop;$script:WelaWecUpdateNativeHash=$hash}
    if($script:WelaWecUpdateNativeHash -cne $hash){throw 'Loaded native updater differs from its current source; start a fresh process.'}
    $edit=[Wela.WecUpdate.Edit]::new($Before.Id)
    try {
        # wecutil formats the embedded query XML. Compare its validated semantic
        # key here; the native handle keeps exact raw strings for its fresh save guard.
        if((ConvertFrom-WelaWefQuery $edit.OriginalQuery).Key -cne $Before.QueryKey -or $edit.OriginalDescription -cne $Before.Description){throw 'Native handle query/description differ from the reviewed definition.'}
        return $edit
    }catch{$edit.Dispose();throw}
}
function Assert-WelaWecUpdatePlan {
    param($Plan)
    Assert-WelaArrivalObject $Plan @('SchemaVersion','Kind','Id','SourceSids','ContextKey','Sources','BeforeXml','QueryXml','Description','RecordedUtc')
    if($Plan.SchemaVersion -isnot [int] -and $Plan.SchemaVersion -isnot [long]){throw 'Plan version must be an integer.'}
    if($Plan.SchemaVersion -ne 1 -or $Plan.Kind -cne 'WelaDisabledWecUpdatePlan' -or $Plan.Id -isnot [string] -or $Plan.SourceSids -isnot [array] -or $Plan.ContextKey -isnot [string] -or $Plan.Sources -isnot [string] -or $Plan.BeforeXml -isnot [string] -or $Plan.QueryXml -isnot [string] -or $Plan.QueryXml.Length -gt 262144 -or $Plan.Description -isnot [string] -or $Plan.Description.Length -gt 4096 -or $Plan.Description -match '[\x00-\x08\x0b\x0c\x0e-\x1f]'){throw 'Unknown or mistyped update plan.'}
    $null=ConvertTo-WelaArrivalUtc $Plan.RecordedUtc
    foreach($sid in $Plan.SourceSids){if($sid -isnot [string]){throw 'Source SID must be a string.'}}
    $null=Get-WelaWefAuthorization $Plan.SourceSids
    $before=Get-WelaWecUpdateDefinition $Plan.BeforeXml $Plan.SourceSids
    if($before.Id -cne $Plan.Id){throw 'Plan identity contradicts its original subscription.'}
    $null=ConvertFrom-WelaWefQuery $Plan.QueryXml
}
function Invoke-WelaWecUpdate {
    param([ValidateSet('Plan','Apply')][string]$Action='Plan',[string]$Id,[string[]]$SourceSids,[string]$QueryPath,[AllowEmptyString()][string]$Description,[string]$PlanPath,[string]$PlanHash,[Parameter(Mandatory)][string]$OutputPath)
    if($Action -eq 'Plan'){
        if(-not $Id -or -not $SourceSids -or -not $QueryPath -or -not $PSBoundParameters.ContainsKey('Description') -or $PlanPath -or $PlanHash){throw 'Plan requires ID, explicit source SIDs, query path, description and new output; no prior plan.'}
    }elseif(-not $PlanPath -or $PlanHash -cnotmatch '^[a-f0-9]{64}$' -or $Id -or $SourceSids -or $QueryPath -or $PSBoundParameters.ContainsKey('Description')){throw 'Apply accepts only a reviewed plan path, its SHA256 and new output.'}
    $sourceInput=if($Action -eq 'Plan'){Read-WelaWecUpdateFile $QueryPath 524288}else{Read-WelaWecUpdateFile $PlanPath}
    $output=New-WelaArrivalOutput $OutputPath $sourceInput.Path
    $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaDisabledWecUpdate';Action=$Action;Status='Failed';ExitCode=1;RecordedUtc=[DateTime]::UtcNow.ToString('o');OutputPath=$output;PlanHash=$null;NativeSaveAttempted=$false;After=$null;Artifacts=@();Diagnostic='';ReadyRuleCredit=0;Scope='Query and description of one disabled subscription only. Delivery, bookmarks, retention and Sigma readiness are unverified. Sysmon excluded.'}
    $edit=$null
    try {
        $context=Get-WelaWecUpdateContext;$contextKey=$context|ConvertTo-Json -Depth 16 -Compress;$sources=Get-WelaWecUpdateSources
        if($Action -eq 'Plan'){
            $null=ConvertFrom-WelaWefQuery $sourceInput.Text
            $before=Read-WelaWecUpdateDefinition $Id $SourceSids
            $plan=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaDisabledWecUpdatePlan';Id=$Id;SourceSids=@($SourceSids);ContextKey=$contextKey;Sources=$sources;BeforeXml=$before.Xml;QueryXml=$sourceInput.Text;Description=$Description;RecordedUtc=[DateTime]::UtcNow.ToString('o')}
            Assert-WelaWecUpdatePlan $plan
            if((Read-WelaWecUpdateFile $QueryPath 524288).Hash -cne $sourceInput.Hash){throw 'Desired query input changed during planning.'}
            if((Read-WelaWecUpdateDefinition $Id $SourceSids).WholeKey -cne $before.WholeKey -or ((Get-WelaWecUpdateContext|ConvertTo-Json -Depth 16 -Compress) -cne $contextKey)){throw 'Host or subscription drift during planning.'}
            $planText=$plan|ConvertTo-Json -Depth 20
            if([Text.Encoding]::UTF8.GetByteCount($planText) -gt 4194304){throw 'The reviewed plan exceeds the four-MiB apply input limit.'}
            $artifact=Write-WelaWecUpdateArtifact $output 'plan.json' $planText;$report.Artifacts+=$artifact;$report.PlanHash=$artifact.Sha256;$report.Status='ReviewRequired';$report.ExitCode=0
        }else{
            if($sourceInput.Hash -cne $PlanHash){throw 'Reviewed plan hash differs from the selected file bytes.'}
            $plan=ConvertFrom-WelaArrivalJson $sourceInput.Text;Assert-WelaWecUpdatePlan $plan;$report.PlanHash=$sourceInput.Hash
            if($plan.ContextKey -cne $contextKey -or $plan.Sources -cne $sources){throw 'Actual host/reader/service or implementation sources differ from the reviewed plan.'}
            $before=Get-WelaWecUpdateDefinition $plan.BeforeXml $plan.SourceSids
            $current=Read-WelaWecUpdateDefinition $plan.Id $plan.SourceSids
            if($current.WholeKey -cne $before.WholeKey){throw 'Current subscription differs from the reviewed complete definition.'}
            $query=ConvertFrom-WelaWefQuery $plan.QueryXml
            $report.Artifacts+=Write-WelaWecUpdateArtifact $output 'reviewed-plan.json' $sourceInput.Text
            if($current.QueryKey -ceq $query.Key -and $current.Description -ceq $plan.Description){$report.Status='AlreadyMatches';$report.ExitCode=0}else{
                $edit=New-WelaWecUpdateEdit $before
                $report.Artifacts+=Write-WelaWecUpdateArtifact $output 'before-save.json' ([ordered]@{Status='Pending';RecordedUtc=[DateTime]::UtcNow.ToString('o');Context=$context;BeforeXml=$before.Xml;DesiredQuery=$plan.QueryXml;DesiredDescription=$plan.Description;PlanHash=$sourceInput.Hash}|ConvertTo-Json -Depth 20)
                if((Read-WelaWecUpdateFile $PlanPath).Hash -cne $PlanHash -or (Get-WelaWecUpdateSources) -cne $sources -or ((Get-WelaWecUpdateContext|ConvertTo-Json -Depth 16 -Compress) -cne $contextKey) -or (Read-WelaWecUpdateDefinition $plan.Id $plan.SourceSids).WholeKey -cne $before.WholeKey){throw 'Plan, code, context or complete subscription changed immediately before save.'}
                $report.NativeSaveAttempted=$true;$edit.Save($plan.QueryXml,$plan.Description)
                $report.Status='SavedAwaitingReadback'
            }
            $after=Read-WelaWecUpdateDefinition $plan.Id $plan.SourceSids;$report.After=$after
            $report.Artifacts+=Write-WelaWecUpdateArtifact $output 'after.xml' $after.Xml
            if($after.QueryKey -cne $query.Key -or $after.Description -cne $plan.Description -or $after.PreservedKey -cne $before.PreservedKey -or ((Get-WelaWecUpdateContext|ConvertTo-Json -Depth 16 -Compress) -cne $contextKey) -or (Get-WelaWecUpdateSources) -cne $sources -or (Read-WelaWecUpdateFile $PlanPath).Hash -cne $PlanHash){throw 'Readback, preserved configuration, context, plan or implementation differs after operation.'}
            if($report.NativeSaveAttempted){$report.Status='UpdatedAndVerified'};$report.ExitCode=0
        }
    }catch{$report.Status=if($report.NativeSaveAttempted){'SaveAttemptedUnverified'}else{'Refused'};$report.ExitCode=1;$report.Diagnostic=$_.Exception.Message}
    finally{if($edit){$edit.Dispose()}}
    $null=Write-WelaWecUpdateArtifact $output 'manifest.json' ($report|ConvertTo-Json -Depth 24)
    $report
}
