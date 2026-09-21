# Reviewed, existing-only Enabled changes; runtime observations are separate evidence.
function Initialize-WelaWecStateNative {
    $path=Join-Path $PSScriptRoot 'WecStateNative.cs';$hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
    if(-not('Wela.WecState.Edit' -as [type])){Add-Type -Path $path -ErrorAction Stop;$script:WelaWecStateNativeHash=$hash}
    if($script:WelaWecStateNativeHash -cne $hash){throw 'Loaded native state setter differs from source; start a fresh process.'}
}
function Get-WelaWecStateContext {
    $context=Get-WelaWecUpdateContext
    Initialize-WelaWecStateNative
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try {$context.Reader=[ordered]@{Name=$identity.Name;Sid=$identity.User.Value;AuthenticationType=$identity.AuthenticationType;ImpersonationLevel=[string]$identity.ImpersonationLevel;Groups=@($identity.Groups.Value|Sort-Object);TokenStatistics=[Wela.WecState.Edit]::TokenKey($identity.Token)}}finally{$identity.Dispose()}
    $channel=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new('ForwardedEvents')
    try {$context|Add-Member NoteProperty DestinationLog ([ordered]@{Name=$channel.LogName;Enabled=$channel.IsEnabled;Mode=[string]$channel.LogMode;MaximumBytes=$channel.MaximumSizeInBytes;Path=$channel.LogFilePath;SecurityDescriptor=$channel.SecurityDescriptor})}finally{$channel.Dispose()}
    $context
}
function Get-WelaWecStateReviewKey {
    param($Context)
    # Separate CLI invocations can hold different token objects in the same logon.
    # Bind plan/apply to the actual logon, and compare complete token statistics
    # within each operation to reject privilege or token changes during writes.
    $copy=$Context|ConvertTo-Json -Depth 16 -Compress|ConvertFrom-Json
    $copy.Reader.TokenStatistics=$Context.Reader.TokenStatistics.Substring(16,16)
    $copy|ConvertTo-Json -Depth 16 -Compress
}
function Get-WelaWecStateSources {
    $root=Split-Path $PSScriptRoot -Parent;$sources=[ordered]@{}
    foreach($name in @('scripts/WecState.ps1','scripts/WecStateNative.cs','scripts/WecUpdate.ps1','modules/WefSubscriptions.psm1','modules/WecSubscriptionXml.cs','scripts/Configuration.ps1','scripts/ControlApplicability.ps1','scripts/WefArrival.ps1','modules/AuditProfiles.psm1','scripts/WecRuntime.ps1','scripts/WecRuntimeNative.cs')){$sources[$name]=(Get-FileHash -LiteralPath (Join-Path $root $name) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()}
    $sources|ConvertTo-Json -Compress
}
function Get-WelaWecStateDefinition {
    param([string]$Xml,[string[]]$SourceSids)
    $model=ConvertFrom-WelaWefSubscription -Xml $Xml -SourceSids $SourceSids -Observed
    $doc=Read-WelaWefXml $Xml;$root=$doc.DocumentElement;$whole=Get-WelaWefXmlKey $root
    $ns=New-Object Xml.XmlNamespaceManager($doc.NameTable);$ns.AddNamespace('s',$root.NamespaceURI)
    $null=$root.RemoveChild($root.SelectSingleNode('s:Enabled',$ns))
    [pscustomobject]@{Id=$model.Id;Xml=$Xml;WholeKey=$whole;PreservedKey=(Get-WelaWefXmlKey $root);Enabled=$model.Definition.Enabled;QueryKey=$model.Query.Key;Description=$model.Definition.Description;SourceAuthorization=$model.Definition.SourceAuthorization}
}
function Read-WelaWecStateDefinition {
    param([string]$Id,[string[]]$SourceSids)
    if($Id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}$'){throw 'Invalid exact subscription ID.'}
    $definition=Get-WelaWecStateDefinition (Read-WelaWecSubscriptionXml $Id) $SourceSids
    if($definition.Id -cne $Id){throw 'Native subscription identity differs from the selected ID.'}
    $definition
}
function New-WelaWecStateEdit {
    param($Before)
    Initialize-WelaWecStateNative
    $edit=[Wela.WecState.Edit]::new($Before.Id)
    try {
        if($edit.OriginalEnabled -ne $Before.Enabled -or (ConvertFrom-WelaWefQuery $edit.OriginalQuery).Key -cne $Before.QueryKey -or $edit.OriginalDescription -cne $Before.Description -or $edit.OriginalAuthorization -cne $Before.SourceAuthorization){throw 'Native handle state differs from the reviewed definition.'}
        $edit
    }catch{$edit.Dispose();throw}
}
function Assert-WelaWecStatePlan {
    param($Plan)
    Assert-WelaArrivalObject $Plan @('SchemaVersion','Kind','Id','SourceSids','ContextKey','Sources','BeforeXml','DesiredEnabled','RecordedUtc')
    if(($Plan.SchemaVersion -isnot [int] -and $Plan.SchemaVersion -isnot [long]) -or $Plan.SchemaVersion -ne 1 -or $Plan.Kind -cne 'WelaWecStatePlan' -or $Plan.Id -isnot [string] -or $Plan.Id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}$' -or $Plan.SourceSids -isnot [array] -or $Plan.ContextKey -isnot [string] -or $Plan.Sources -isnot [string] -or $Plan.BeforeXml -isnot [string] -or $Plan.DesiredEnabled -isnot [bool]){throw 'Unknown or mistyped state plan.'}
    $null=ConvertTo-WelaArrivalUtc $Plan.RecordedUtc
    foreach($sid in $Plan.SourceSids){if($sid -isnot [string]){throw 'Source SID must be a string.'}}
    $null=Get-WelaWefAuthorization $Plan.SourceSids
    $before=Get-WelaWecStateDefinition $Plan.BeforeXml $Plan.SourceSids
    if($before.Id -cne $Plan.Id){throw 'Plan identity contradicts its original subscription.'}
}
function Read-WelaWecStateRuntime {
    param([string]$Id)
    try {Get-WelaWecRuntime -Id $Id -MaximumSources 32}
    catch {[pscustomobject]@{Status='Unknown';Diagnostic=$_.Exception.Message;ReadyRuleCredit=0}}
}
function Assert-WelaWecStateArtifacts {
    param([string]$Root,$Artifacts)
    foreach($artifact in $Artifacts){if((Get-FileHash -LiteralPath (Join-Path $Root $artifact.Name) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() -cne $artifact.Sha256){throw 'Saved state evidence changed before completion.'}}
}
function Invoke-WelaWecState {
    param([ValidateSet('Plan','Apply')][string]$Action='Plan',[string]$Id,[string[]]$SourceSids,[ValidateSet('Enabled','Disabled')][string]$State,[string]$PlanPath,[string]$PlanHash,[Parameter(Mandatory)][string]$OutputPath)
    $ErrorActionPreference='Stop'
    if($Action -eq 'Plan'){
        if(-not $Id -or -not $SourceSids -or -not $State -or $PlanPath -or $PlanHash){throw 'Plan requires exact ID, explicit source SIDs, Enabled or Disabled state and new output; no prior plan.'}
        $sourceInput=$null;$sourcePath=Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts'
    }else{
        if(-not $PlanPath -or $PlanHash -cnotmatch '^[a-f0-9]{64}$' -or $Id -or $SourceSids -or $State){throw 'Apply accepts only a reviewed plan path, its SHA256 and new output.'}
        $sourceInput=Read-WelaWecUpdateFile $PlanPath;$sourcePath=$sourceInput.Path
    }
    $output=New-WelaArrivalOutput $OutputPath $sourcePath
    $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaWecState';Action=$Action;Status='Refused';ExitCode=1;RecordedUtc=[DateTime]::UtcNow.ToString('o');OutputPath=$output;PlanHash=$null;BeforeEnabled=$null;DesiredEnabled=$null;NativeSaveAttempted=$false;NativeErrorCode=$null;After=$null;RuntimeBefore=$null;RuntimeAfter=$null;Artifacts=@();Diagnostic='';ReadyRuleCredit=0;Delivery='Not established';BookmarkContinuity='Not established';Scope='Only Enabled on one existing native source-initiated subscription. Disable interrupts collection; enable/save activates it. No listener, firewall, service or authorization changes. Sysmon excluded.'}
    $edit=$null;$plan=$null;$before=$null
    try {
        $context=Get-WelaWecStateContext;$contextKey=$context|ConvertTo-Json -Depth 16 -Compress;$sources=Get-WelaWecStateSources
        if($Action -eq 'Plan'){
            $before=Read-WelaWecStateDefinition $Id $SourceSids
            $plan=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaWecStatePlan';Id=$Id;SourceSids=@($SourceSids);ContextKey=(Get-WelaWecStateReviewKey $context);Sources=$sources;BeforeXml=$before.Xml;DesiredEnabled=($State -eq 'Enabled');RecordedUtc=[DateTime]::UtcNow.ToString('o')}
            Assert-WelaWecStatePlan $plan
            if($plan.DesiredEnabled -and -not $context.DestinationLog.Enabled){throw 'ForwardedEvents must already be enabled before planning activation; no channel changes are made.'}
            $report.RuntimeBefore=Read-WelaWecStateRuntime $Id
            if((Read-WelaWecStateDefinition $Id $SourceSids).WholeKey -cne $before.WholeKey -or ((Get-WelaWecStateContext|ConvertTo-Json -Depth 16 -Compress) -cne $contextKey) -or (Get-WelaWecStateSources) -cne $sources){throw 'Host, reader, implementation or subscription drift during planning.'}
            $planText=$plan|ConvertTo-Json -Depth 20
            if([Text.Encoding]::UTF8.GetByteCount($planText) -gt 4194304){throw 'Reviewed plan exceeds the four-MiB apply limit.'}
            $artifact=Write-WelaWecUpdateArtifact $output 'plan.json' $planText;$report.Artifacts+=$artifact;$report.PlanHash=$artifact.Sha256;$report.Status='ReviewRequired'
        }else{
            if($sourceInput.Hash -cne $PlanHash){throw 'Reviewed plan hash differs from the selected file bytes.'}
            $plan=ConvertFrom-WelaArrivalJson $sourceInput.Text;Assert-WelaWecStatePlan $plan;$report.PlanHash=$sourceInput.Hash
            if($plan.DesiredEnabled -and -not $context.DestinationLog.Enabled){throw 'ForwardedEvents must already be enabled before activation; no channel changes are made.'}
            if($plan.ContextKey -cne (Get-WelaWecStateReviewKey $context) -or $plan.Sources -cne $sources){throw 'Actual host/reader/token/service or implementation sources differ from the reviewed plan.'}
            $before=Get-WelaWecStateDefinition $plan.BeforeXml $plan.SourceSids
$report.BeforeEnabled=$before.Enabled;$report.DesiredEnabled=$plan.DesiredEnabled
            $report.RuntimeBefore=Read-WelaWecStateRuntime $plan.Id
            if((Read-WelaWecStateDefinition $plan.Id $plan.SourceSids).WholeKey -cne $before.WholeKey){throw 'Current subscription differs from the reviewed complete definition.'}
            $report.Artifacts+=Write-WelaWecUpdateArtifact $output 'reviewed-plan.json' $sourceInput.Text
            if($before.Enabled -eq $plan.DesiredEnabled){$report.Status='AlreadyMatches'}else{
                $edit=New-WelaWecStateEdit $before
                $report.Artifacts+=Write-WelaWecUpdateArtifact $output 'before-save.json' ([ordered]@{Status='Pending';RecordedUtc=[DateTime]::UtcNow.ToString('o');Context=$context;BeforeXml=$before.Xml;DesiredEnabled=$plan.DesiredEnabled;PlanHash=$sourceInput.Hash}|ConvertTo-Json -Depth 20)
                Assert-WelaWecStateArtifacts $output $report.Artifacts
                if((Read-WelaWecUpdateFile $PlanPath).Hash -cne $PlanHash -or (Get-WelaWecStateSources) -cne $sources -or ((Get-WelaWecStateContext|ConvertTo-Json -Depth 16 -Compress) -cne $contextKey) -or (Read-WelaWecStateDefinition $plan.Id $plan.SourceSids).WholeKey -cne $before.WholeKey){throw 'Plan, code, context or complete subscription changed immediately before save.'}
                try {$edit.Save($plan.DesiredEnabled)}finally{$report.NativeSaveAttempted=[bool]$edit.SaveAttempted}
                $report.Status='SavedAwaitingReadback'
            }
            $report.RuntimeAfter=Read-WelaWecStateRuntime $plan.Id
            $after=Read-WelaWecStateDefinition $plan.Id $plan.SourceSids;$report.After=$after
            $report.Artifacts+=Write-WelaWecUpdateArtifact $output 'after.xml' $after.Xml
            if($after.Enabled -ne $plan.DesiredEnabled -or $after.PreservedKey -cne $before.PreservedKey -or ((Get-WelaWecStateContext|ConvertTo-Json -Depth 16 -Compress) -cne $contextKey) -or (Get-WelaWecStateSources) -cne $sources -or (Read-WelaWecUpdateFile $PlanPath).Hash -cne $PlanHash){throw 'Readback, preserved configuration, context, plan or implementation differs after operation.'}
            if($report.NativeSaveAttempted){$report.Status='StateChangedAndVerified'}
        }
        $report.BeforeEnabled=$before.Enabled;$report.DesiredEnabled=$plan.DesiredEnabled
        Assert-WelaWecStateArtifacts $output $report.Artifacts
        $report.ExitCode=0
    }catch{
        $report.Status=if($report.NativeSaveAttempted){'SaveAttemptedUnverified'}else{'Refused'};$report.ExitCode=1;$report.Diagnostic=$_.Exception.Message
        $errorObject=$_.Exception
        while($errorObject){if($errorObject -is [ComponentModel.Win32Exception]){$report.NativeErrorCode=$errorObject.NativeErrorCode;break};$errorObject=$errorObject.InnerException}
        if($report.NativeSaveAttempted -and $plan){
            # A failed activation can still persist Enabled. Never imply rollback.
            $report.RuntimeAfter=Read-WelaWecStateRuntime $plan.Id
            try {$report.After=Read-WelaWecStateDefinition $plan.Id $plan.SourceSids;$report.Artifacts+=Write-WelaWecUpdateArtifact $output 'failed-after.xml' $report.After.Xml}
            catch {$report.Diagnostic+=' Final definition unavailable: '+$_.Exception.Message}
        }
    }
    finally{if($edit){$edit.Dispose()}}
    $null=Write-WelaWecUpdateArtifact $output 'manifest.json' ($report|ConvertTo-Json -Depth 32)
    $report
}
