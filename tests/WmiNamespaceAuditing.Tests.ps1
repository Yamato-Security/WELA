# In-memory descriptors only. All native readers/writers are replaced before control execution.
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$script:ScriptRoot = $repo
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/WmiNamespaceAuditing.ps1')
$script:assertions = 0
$root = Join-Path ([IO.Path]::GetTempPath()) ('wela-wmi-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $root
$fixture = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures/wmi-namespace-descriptor.json') -Raw
function Assert($Condition, [string]$Message) { if (-not $Condition) { throw "FAIL: $Message" }; $script:assertions++ }
function Throws([scriptblock]$Action, [string]$Message) { $caught = $false; try { & $Action } catch { $caught = $true }; Assert $caught $Message }
function Reset-Mocks {
    $script:descriptor = $fixture | ConvertFrom-Json
    $script:writes = 0; $script:reads = 0; $script:readFail = $false; $script:writeCode = 0
    $script:race = $false; $script:alterOwner = $false; $script:dropUnknown = $false; $script:ineffective = $false
    $script:decline = $false; $script:promptCallback = $null
}
function Get-WelaWmiNamespaceSnapshot {
    param($Namespace)
    $script:reads++
    if ($script:readFail) { throw 'Access denied or namespace missing; no complete SACL available.' }
    [pscustomobject]@{ Namespace = $Namespace; DescriptorJson = ConvertTo-WelaWmiJson $script:descriptor; DescriptorMof = 'mock full descriptor'; SaclReadPrivilege = 'mock assigned/enabled' }
}
function Set-WelaWmiNamespaceDescriptor {
    param($Namespace, $ExpectedJson, $Definitions)
    # Model the production immediate re-read and verify the generic runner journal.
    $entry = @(Get-Content -LiteralPath (Join-Path $script:context.BackupPath 'before.jsonl') | ConvertFrom-Json)[-1]
    Assert ($entry.Before.DescriptorJson -ceq $ExpectedJson -and $entry.Target.Namespace -eq $Namespace) 'Full recovery descriptor persisted before any setter'
    Assert ($entry.Before.DescriptorMof -eq 'mock full descriptor') 'Journal includes native descriptor representation'
    if ($script:race) { $script:descriptor.Owner.SIDString = 'S-1-5-18' }
    if ((ConvertTo-WelaWmiJson $script:descriptor) -cne $ExpectedJson) { throw 'Namespace descriptor changed after its recovery snapshot; no SACL was written.' }
    $script:writes++
    Assert-WelaWmiReturnCode ([pscustomobject]@{ ReturnValue = $script:writeCode }) 'SetSecurityDescriptor'
    if ($script:ineffective) { return }
    foreach ($definition in @(Get-WelaWmiMissingAces $script:descriptor $Definitions)) {
        $script:descriptor.SACL += [pscustomobject]@{ AccessMask = $definition.AccessMask; AceFlags = $definition.AceFlags; AceType = 2; Trustee = [pscustomobject]@{ SIDString = $definition.Sid } }
    }
    $script:descriptor.ControlFlags = [uint32]$script:descriptor.ControlFlags -bor 16
    if ($script:alterOwner) { $script:descriptor.Owner.SIDString = 'S-1-5-18' }
    if ($script:dropUnknown) { $script:descriptor.SACL = @($script:descriptor.SACL | Where-Object AceType -ne 19) }
}
function Read-Host { param($Prompt) if ($script:promptCallback) { & $script:promptCallback }; if ($script:decline) { 'n' } else { 'Y' } }
function New-TestContext([switch]$DryRun, [switch]$Prompt) {
    $script:context = New-WelaConfigurationContext -Auto:(-not $Prompt) -DryRun:$DryRun -BackupPath (Join-Path $root ([guid]::NewGuid().ToString('N')))
    return $script:context
}
function Run-Controls { param($Context, [string[]]$Namespace = @('root\cimv2'), [switch]$IncludeChildren)
    Set-WelaWmiAuditControls -Context $Context -Plan @(Get-WelaWmiAuditPlan -Namespace $Namespace -IncludeChildren:$IncludeChildren)
}
try {
    $source = @(Get-WelaWmiAuditDefinitions -IncludeChildren)
    Assert ($source.Count -eq 8) 'All eight pinned ASD entries are represented'
    Assert (@($source.Namespace | Select-Object -Unique).Count -eq 5) 'Exactly five supported namespaces'
    $expected = @('root\cimv2|262146|64|S-1-1-0', 'root\cimv2|1|64|S-1-5-4', 'root\cimv2|1|64|S-1-5-2', 'root\cimv2|1|64|S-1-5-3', 'root\SecurityCenter|262145|66|S-1-1-0', 'root\SecurityCenter2|262145|66|S-1-1-0', 'root\subscription|262174|66|S-1-1-0', 'root\default|262175|66|S-1-1-0')
    foreach ($i in 0..7) { Assert (("$($source[$i].Namespace)|$($source[$i].AccessMask)|$($source[$i].AceFlags)|$($source[$i].Sid)") -eq $expected[$i]) 'Masks, principals and inheritance match pinned ASD source' }
    Assert (@(Get-WelaWmiAuditDefinitions | Where-Object AceFlags -ne 64).Count -eq 0) 'Default does not extend auditing into unselected descendants'
    Assert (@(Get-WelaWmiAuditDefinitions -Namespace @('ROOT\CIMV2','root\cimv2')).Count -eq 4) 'Case-insensitive duplicate selections do not duplicate ACE definitions'
    foreach ($invalid in @('root\*','\\server\root\cimv2','root/cimv2','root\cimv2\child','root\default ')) { Throws { Get-WelaWmiAuditDefinitions -Namespace $invalid } 'Wildcards, remote paths and unreviewed namespace targets rejected' }
    Throws { Get-WelaWmiAuditPlan } 'Empty selection refuses implicit configuration'
    foreach ($value in @(2,8,9,21,4294967295,$null,$false,'unknown')) {
        Throws { Assert-WelaWmiReturnCode ([pscustomobject]@{ReturnValue=$value}) 'GetSecurityDescriptor' } 'Every nonzero/missing/invalid return fails'
        Throws { Assert-WelaWmiReturnCode ([pscustomobject]@{ReturnValue=$value}) 'SetSecurityDescriptor' } 'Every setter error is checked'
    }
    Assert-WelaWmiReturnCode ([pscustomobject]@{ReturnValue=[uint32]0}) 'GetSecurityDescriptor'
    $getter = [pscustomobject]@{ Code = 2; Descriptor = [pscustomobject]@{ControlFlags=4} }
    $getter | Add-Member ScriptMethod InvokeMethod { param($Name,$Parameters,$Options) [pscustomobject]@{ReturnValue=$this.Code;Descriptor=$this.Descriptor} }
    Throws { Get-WelaWmiNativeDescriptor $getter } 'Production getter checks provider return code even when descriptor is populated'
    $getter.Code=0; $getter.Descriptor=$null
    Throws { Get-WelaWmiNativeDescriptor $getter } 'Production getter refuses missing descriptor even with success code'
    $getter.Descriptor=[pscustomobject]@{ControlFlags=4;SACL=$null}
    Assert ((Get-WelaWmiNativeDescriptor $getter).ControlFlags -eq 4) 'Production getter accepts explicit success and descriptor'
    Assert ((Get-WelaWmiSid ([pscustomobject]@{ SID = [byte[]]@(1,1,0,0,0,0,0,1,0,0,0,0) })) -eq 'S-1-1-0') 'Binary SID identity supported without localized names'
    Reset-Mocks
    $before = $script:descriptor | ConvertTo-Json -Depth 30 | ConvertFrom-Json
    $context = New-TestContext -DryRun
    Run-Controls $context
    Assert ($script:writes -eq 0 -and -not (Test-Path $context.BackupPath) -and $context.Results[0].Status -eq 'Skipped') 'Dry-run has no setter or journal mutation'
    $context = New-TestContext -Prompt; $script:decline = $true
    Run-Controls $context
    Assert ($script:writes -eq 0 -and $context.Results[0].Diagnostic -match 'Declined') 'Operator decline has no setter'
    Reset-Mocks
    $context = New-TestContext
    Run-Controls $context
    Assert ($script:writes -eq 1 -and $context.Results[0].Status -eq 'Applied') 'One namespace update appends four missing CIMV2 ACEs'
    Assert ((Complete-WelaConfiguration $context -Scope wmi-namespace-sacl-only).ExitCode -eq 0) 'Applied namespace passes final verification'
    Assert (Test-WelaWmiDescriptorPreserved $before $script:descriptor) 'Owner/group/DACL/control flags and duplicate unknown ACEs preserved'
    Assert ($script:descriptor.ControlFlags -eq (36868 -bor 16)) 'Only SACL_PRESENT is added to descriptor control flags'
    Assert ($script:descriptor.SACL.Count -eq 7 -and @($script:descriptor.SACL | Where-Object AceType -eq 19).Count -eq 2) 'Unknown ACE multiplicity preserved'
    $context = New-TestContext
    Run-Controls $context
    Assert ($script:writes -eq 1 -and $context.Results[0].Status -eq 'AlreadyCompliant') 'Second run does not duplicate entries'
    $script:descriptor.DACL[0].AccessMask = 1
    Assert ((Complete-WelaConfiguration $context).ExitCode -eq 1 -and $context.Results[0].Status -eq 'Overridden') 'Final already-compliant DACL drift is detected'
    Reset-Mocks; $context = New-TestContext; $script:race = $true
    Run-Controls $context
    Assert ($script:writes -eq 0 -and $context.Results[0].Status -eq 'Failed') 'Changed owner between journal and setter refuses update'
    Reset-Mocks; $context = New-TestContext -Prompt
    $script:promptCallback = { $script:descriptor.SACL[1].OpaqueFutureField = @(99) }
    Run-Controls $context
    Assert ($script:writes -eq 0 -and $context.Results[0].Status -eq 'Failed') 'Unknown ACE changes during operator prompt are preserved by refusing write'
    foreach ($failure in @('alterOwner','dropUnknown','ineffective')) {
        Reset-Mocks; Set-Variable -Scope Script -Name $failure -Value $true; $context = New-TestContext
        Run-Controls $context
        Assert ($context.Results[0].Status -eq 'Failed' -and (Complete-WelaConfiguration $context).ExitCode -eq 1) 'Read-back rejects permission damage, dropped unknown ACE or ineffective update'
    }
    Reset-Mocks; $script:writeCode = 9; $context = New-TestContext
    Run-Controls $context
    Assert ($context.Results[0].Status -eq 'Failed' -and $script:descriptor.SACL.Count -eq 3) 'Provider return-code error is a failed control'
    Reset-Mocks; $script:readFail = $true; $context = New-TestContext
    Run-Controls $context
    Assert ($script:writes -eq 0 -and $context.Results[0].Status -eq 'Failed') 'Unreadable/missing selected namespace fails without partial descriptor writes'
    Reset-Mocks; $context = New-TestContext
    Remove-Item -LiteralPath $context.BackupPath -Recurse
    Run-Controls $context
    Assert ($script:writes -eq 0 -and $context.Results[0].Status -eq 'Failed') 'Journal failure prevents setter invocation'
    Reset-Mocks; $context = New-TestContext
    Run-Controls $context
    $script:descriptor.SACL += [pscustomobject]@{ AceType=2; AceFlags=128; AccessMask=1; Trustee=[pscustomobject]@{SIDString='S-1-5-18'} }
    Assert ((Complete-WelaConfiguration $context).ExitCode -eq 1 -and $context.Results[0].Status -eq 'Overridden') 'Extra SACL drift after successful write is detected at final check'
    Reset-Mocks; $context = New-TestContext
    Run-Controls $context -Namespace 'root\subscription' -IncludeChildren
    Assert ($script:descriptor.SACL[-1].AceFlags -eq 66 -and $script:descriptor.SACL[-1].AccessMask -eq 262174) 'Explicit child option enables exactly ASD inheritance for subscription'
    $definition = @(Get-WelaWmiAuditDefinitions -Namespace 'root\cimv2')[0]
    $ace = [pscustomobject]@{AceType=2;AceFlags=64;AccessMask=262146;Trustee=[pscustomobject]@{SIDString='S-1-1-0'}}
    Assert (Test-WelaWmiAceMatch $ace $definition) 'Exact ordinary success ACE satisfies requirement'
    foreach ($flags in @(80,192,66,72)) { $ace.AceFlags=$flags; Assert (-not (Test-WelaWmiAceMatch $ace $definition)) 'Inherited/broader/different-scope ACE does not hide a missing exact request' }
    $tokens=$null;$parseErrors=$null
    $ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'WELA.ps1'),[ref]$tokens,[ref]$parseErrors)
    Assert ($parseErrors.Count -eq 0) 'Combined CLI parses'
    # Execute only the actual top-level DryRun guard, with no command dispatch.
    $guard=$ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.IfStatementAst] -and $_.Extent.Text.StartsWith('if ($DryRun') } | Select-Object -First 1
    $Cmd='wmi-auditing';$DryRun=$true;$WmiAction='Configure';$FirewallAction='Audit';$SmbAction='Audit'
    & ([scriptblock]::Create($guard.Extent.Text));$WmiAction='Audit'
    Throws { & ([scriptblock]::Create($guard.Extent.Text)) } 'WMI Audit rejects DryRun before dispatch'
    Write-Host "PASS: $script:assertions WMI namespace assertions (mocked, no live namespace changes)."
} finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
