$ErrorActionPreference='Stop'
$script:ScriptRoot=Split-Path $PSScriptRoot -Parent
. (Join-Path $script:ScriptRoot 'scripts/Configuration.ps1')
. (Join-Path $script:ScriptRoot 'scripts/LdapDiagnostics.ps1')
$script:count=0
function Assert($Condition,$Message) { if (-not $Condition) { throw $Message }; $script:count++ }
function Reject([scriptblock]$Action,[string]$Pattern) {
    $message=''; try { & $Action | Out-Null } catch { $message=$_.Exception.Message }
    Assert ($message -match $Pattern) "Expected '$Pattern', got '$message'."
}
function Reset-Fixture {
    $script:values=@{}; $script:writes=@(); $script:role='Applicable'; $script:readError=$false
    $script:writeError=$false; $script:ignoreWrite=$false; $script:race=$false; $script:reads=0
    $script:types=@{}; $script:journal=$null; $script:failName=$null
}
function Get-WelaLdapHost { [pscustomobject]@{Status=$script:role;Diagnostic='fixture';ComputerName='dc1';Build=26100} }
function Get-WelaRegistryState {
    param($Path,$Name)
    if ($script:readError) { throw 'read denied' }
    $script:reads++
    if ($script:race -and $script:journal -and (Test-Path $script:journal)) { $script:values['15 Field Engineering']=4; $script:types['15 Field Engineering']='DWord' }
    [pscustomobject]@{KeyExists=$true;ValueExists=$script:values.ContainsKey($Name);Value=$script:values[$Name];Type=$script:types[$Name]}
}
function New-WelaRegistryKey { param($Path) }
function Set-ItemProperty {
    param($LiteralPath,$Name,$Value,$Type,$ErrorAction)
    Assert ($script:journal -and (Test-Path $script:journal)) 'Every native write must follow the complete pre-change journal.'
    if ($script:writeError -or $Name -eq $script:failName) { throw 'write denied' }
    $script:writes += $Name
    if (-not $script:ignoreWrite) { $script:values[$Name]=$Value; $script:types[$Name]=$Type }
}
function Remove-ItemProperty {
    param($LiteralPath,$Name,$ErrorAction)
    Assert ($script:journal -and (Test-Path $script:journal)) 'Every removal must follow a recovery journal.'
    if ($script:writeError -or $Name -eq $script:failName) { throw 'remove denied' }
    $script:writes += $Name
    if (-not $script:ignoreWrite) { $script:values.Remove($Name); $script:types.Remove($Name) }
}
$cleanup=@()
function New-FixtureContext([switch]$DryRun) {
    $path=Join-Path ([IO.Path]::GetTempPath()) ('wela-ldap-'+[guid]::NewGuid().ToString('N'))
    $script:cleanup += $path; $script:journal=Join-Path $path 'before.jsonl'
    New-WelaConfigurationContext -Auto -DryRun:$DryRun -BackupPath $path
}
try {
    Reset-Fixture
    foreach ($mode in @('Preserve','Diagnostic','MdiCleanup')) {
        $plan=Get-WelaLdapPlan (Get-WelaLdapSnapshot) $mode
        Assert ($plan.Controls.Count -eq 4 -and $plan.VerificationScope -match 'not established') 'Every plan enumerates the complete bounded set and keeps event evidence separate.'
    }
    foreach ($value in @(-1,0,1.5,2147483648,$true)) {
        Reject { Get-WelaLdapPlan (Get-WelaLdapSnapshot) Diagnostic @{SearchTime=$value} } 'Invalid'
    }
    Reject { Get-WelaLdapPlan (Get-WelaLdapSnapshot) MdiCleanup @{SearchTime=1} } 'require Diagnostic'
    Reject { Get-WelaLdapPlan (Get-WelaLdapSnapshot) Diagnostic @{Typo=1} } 'Invalid'
    $script:values['15 Field Engineering']=4; $script:types['15 Field Engineering']='DWord'
    $preserved=Invoke-WelaLdapCommand -Action Configure
    Assert ($script:writes.Count -eq 0 -and $preserved.Plan.Mode -eq 'Preserve' -and $script:values['15 Field Engineering'] -eq 4) 'Default command preserves another operator diagnostic level.'

    foreach ($scenario in @('apply','dry','cleanup','read','write','ignored','race','type','drift','preserved-drift','stale')) {
        Reset-Fixture
        $mode='Diagnostic'; $thresholds=@{SearchTime=100;Expensive=10000;Inefficient=1000}
        if ($scenario -eq 'cleanup') {
            $mode='MdiCleanup'; $thresholds=@{}
            foreach ($definition in Get-WelaLdapDefinitions) { $script:values[$definition.Name]=1; $script:types[$definition.Name]='DWord' }
            $script:values['15 Field Engineering']=5
        }
        if ($scenario -eq 'preserved-drift') { $thresholds=@{} }
        if ($scenario -eq 'type') { $script:values['15 Field Engineering']='5'; $script:types['15 Field Engineering']='String' }
        $plan=Get-WelaLdapPlan (Get-WelaLdapSnapshot) $mode $thresholds
        if ($scenario -eq 'read') { $script:readError=$true }
        if ($scenario -eq 'write') { $script:writeError=$true }
        if ($scenario -eq 'ignored') { $script:ignoreWrite=$true }
        if ($scenario -eq 'race') { $script:race=$true }
        if ($scenario -eq 'stale') { $script:values['15 Field Engineering']=2; $script:types['15 Field Engineering']='DWord' }
        $context=New-FixtureContext -DryRun:($scenario -eq 'dry')
        Set-WelaLdapDiagnostics $context $plan
        if ($scenario -eq 'drift') { $script:values['15 Field Engineering']=0 }
        if ($scenario -eq 'preserved-drift') { $script:values['Expensive Search Results Threshold']=5; $script:types['Expensive Search Results Threshold']='DWord' }
        $result=Complete-WelaConfiguration $context
        switch ($scenario) {
            'apply' {
                Assert ($result.ExitCode -eq 0 -and $script:writes.Count -eq 4 -and $script:writes[-1] -eq '15 Field Engineering') 'Verify thresholds before enabling verbosity.'
                $before=Get-Content $script:journal -Raw | ConvertFrom-Json
                Assert ($before.Before.Values.Count -eq 4 -and @($before.Before.Values | Where-Object {$_.State.ValueExists}).Count -eq 0) 'Journal contains all exact missing-value states.'
                $again=Get-WelaLdapPlan (Get-WelaLdapSnapshot) Diagnostic $thresholds
                Set-WelaLdapDiagnostics $context $again
                Assert ($script:writes.Count -eq 4 -and $context.Results[1].Status -eq 'AlreadyCompliant') 'Repeat configuration performs no duplicate writes.'
            }
            'dry' { Assert ($result.ExitCode -eq 0 -and $script:writes.Count -eq 0 -and -not (Test-Path $context.BackupPath)) 'Dry-run makes no settings/journal changes.' }
            'cleanup' { Assert ($result.ExitCode -eq 0 -and $script:values.Count -eq 0 -and $script:writes[0] -eq '15 Field Engineering') 'Explicit MDI cleanup removes only named values, verbosity first.' }
            'ignored' { Assert ($result.ExitCode -eq 1 -and $script:writes.Count -eq 1 -and $script:writes -notcontains '15 Field Engineering') 'Failed threshold readback cannot proceed to enabling diagnostics.' }
            'drift' { Assert ($result.ExitCode -eq 1 -and $context.Results[0].Status -eq 'Overridden') 'Final diagnostic drift fails.' }
            'preserved-drift' { Assert ($result.ExitCode -eq 1) 'Unselected thresholds must remain preserved.' }
            default { Assert ($result.ExitCode -eq 1 -and $script:writes.Count -eq 0) "Scenario $scenario must block before native writes." }
        }
    }
    # Exercise actual partial mutation boundaries: recovery is journal-based and
    # does not automatically overwrite the successfully changed subset.
    foreach ($mode in @('Diagnostic','MdiCleanup')) {
        Reset-Fixture
        $thresholds=@{SearchTime=100;Expensive=10000;Inefficient=1000}
        if ($mode -eq 'MdiCleanup') {
            $thresholds=@{}
            foreach ($definition in Get-WelaLdapDefinitions) { $script:values[$definition.Name]=1; $script:types[$definition.Name]='DWord' }
            $script:values['15 Field Engineering']=5
            $script:failName='Search Time Threshold (msecs)'
        } else { $script:failName='15 Field Engineering' }
        $script:values['Unrelated diagnostic']=7; $script:types['Unrelated diagnostic']='DWord'
        $plan=Get-WelaLdapPlan (Get-WelaLdapSnapshot) $mode $thresholds
        $context=New-FixtureContext
        Set-WelaLdapDiagnostics $context $plan
        $result=Complete-WelaConfiguration $context
        $journal=Get-Content $script:journal -Raw | ConvertFrom-Json
        Assert ($result.ExitCode -eq 1 -and $journal.Before.Values.Count -eq 4) 'A failure after earlier writes retains the complete recovery snapshot.'
        Assert ($script:values['Unrelated diagnostic'] -eq 7) 'Partial failures preserve unrelated registry values.'
        if ($mode -eq 'Diagnostic') {
            Assert ($script:writes.Count -eq 3 -and -not $script:values.ContainsKey('15 Field Engineering')) 'Failed verbosity write leaves verified thresholds and does not claim success.'
        } else {
            Assert ($script:writes.Count -eq 1 -and -not $script:values.ContainsKey('15 Field Engineering') -and $script:values['Search Time Threshold (msecs)'] -eq 1 -and $script:values['Expensive Search Results Threshold'] -eq 1 -and $script:values['Inefficient Search Results Threshold'] -eq 1) 'Cleanup stops after the first failed threshold removal without restoring verbosity or removing later values.'
        }
    }
    Reset-Fixture; $script:role='NotApplicable'
    $report=Invoke-WelaLdapCommand -Action Audit
    Assert ($report.Snapshot.Values.Count -eq 0 -and $script:reads -eq 0) 'Member/client/non-DC CA never queries or creates NTDS settings.'
    Reject { Invoke-WelaLdapCommand -Action Configure -Mode Diagnostic } 'blocked'
    Reset-Fixture; $script:role='Unknown'
    Assert ((Invoke-WelaLdapCommand).ExitCode -eq 1) 'Unknown host applicability cannot look successful.'

    # Execute the real general configure body with all native boundaries replaced.
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $script:ScriptRoot 'WELA.ps1'),[ref]$null,[ref]$null)
    # Preserve the real ordering of the LDAP guard and early profile dispatch, while
    # replacing the profile handler so configure can never change this test host.
    $dispatchNodes=@($ast.EndBlock.Statements | Where-Object {
        $_ -is [Management.Automation.Language.IfStatementAst] -and
        ($_.Extent.Text -match 'LDAP options require' -or $_.Extent.Text -match 'Invoke-WelaProfileCommand -Command')
    })
    Assert ($dispatchNodes.Count -eq 2) 'Exercise both real CLI boundaries in source order.'
    $dispatch=[scriptblock]::Create('param($Cmd,$Profile,$LdapAction,$LdapMode,$LdapSearchTimeMs,$LdapExpensiveThreshold,$LdapInefficientThreshold)' + [Environment]::NewLine + (($dispatchNodes | ForEach-Object {$_.Extent.Text}) -join [Environment]::NewLine))
    function Invoke-WelaProfileCommand { param($Command) $script:profileDispatched=$true }
    foreach ($command in @('plan','audit','audit-settings','configure')) {
        foreach ($option in @('LdapAction','LdapMode','LdapSearchTimeMs','LdapExpensiveThreshold','LdapInefficientThreshold')) {
            $script:profileDispatched=$false
            $arguments=@{Cmd=$command;Profile='fixture'}; $arguments[$option]='fixture'
            Reject { & $dispatch @arguments } 'LDAP options require'
            Assert (-not $script:profileDispatched) "LDAP option $option must block $command before unrelated profile dispatch."
        }
    }
    $node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'ConfigureAuditSettings'},$false)
    . ([scriptblock]::Create($node.Extent.Text))
    function TestWindows {$true}; function TestAdministrator {$true}
    function Get-WelaHostContext {[pscustomobject]@{Role='DomainController';Build=26100}}
    function Get-WelaEffectiveAuditPolicy {@{}}
    function Get-WelaAuditProfilePlan {[pscustomobject]@{profile='fixture'}}
    function Assert-WelaAuditProfileTarget {}
    function Set-WelaEventLogProfileControls {}
    function Set-WelaEventLogControl {}
    function Set-WelaRegistryControl {param($Context,$Path,$Name) if ($Path -like '*NTDS*') {throw 'General configure attempted NTDS diagnostics'} }
    function Set-RegistryConfig {param($RegPaths) if (@($RegPaths | Where-Object {$_.Path -like '*NTDS*'}).Count) {throw 'General configure attempted NTDS diagnostics'} }
    function Set-WelaOutgoingNtlmPolicy {};function Set-WelaDomainNtlmAudit {};function Show-WelaAuditProfilePrerequisites {};function Set-WelaProfileAuditControls {};function Set-WelaCertificateAuditControl {}
    function Complete-WelaConfiguration {[pscustomobject]@{ExitCode=0}}
    $script:PowerShellPolicyRoots=@(); $script:IncludeOptional=$false
    $general=ConfigureAuditSettings -Auto -DryRun
    Assert ($general.ExitCode -eq 0) 'Normal DC configure must not re-enable or disable LDAP diagnostics.'
    Write-Host "PASS: $script:count LDAP diagnostics assertions; no Windows changes."
} finally { foreach ($path in $cleanup) { if (Test-Path $path) { Remove-Item $path -Recurse -Force } } }
