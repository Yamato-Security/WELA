# Real Windows descriptor API tests and read-only metadata/CLI smoke. No channel writes.
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/EventLogSettings.psm1') -Force
Import-Module (Join-Path $repo 'modules/NativeProviders.psm1') -Force
Import-Module (Join-Path $repo 'modules/NativeChannelAccess.psm1') -Force
$script:assertions = 0
function Assert($Condition, [string]$Message) {
    if (-not $Condition) { throw "FAIL: $Message" }; $script:assertions++
}
function Binary($Value) {
    $bytes = New-Object byte[] $Value.BinaryLength
    $Value.GetBinaryForm($bytes, 0)
    [Convert]::ToBase64String($bytes)
}
function Check-Preservation([string]$Sddl) {
    $before = [System.Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
    $plan = Get-WelaChannelAccessPlan -SecurityDescriptor $Sddl
    Assert ($plan.State -eq 'GrantRequired') "Descriptor supports lossless append: $($plan.Diagnostic)"
    $after = [System.Security.AccessControl.RawSecurityDescriptor]::new($plan.ProposedDescriptor)
    Assert ($before.Owner -eq $after.Owner -and $before.Group -eq $after.Group) 'Owner/group are retained'
    Assert ($before.ControlFlags -eq $after.ControlFlags -and $before.ResourceManagerControl -eq $after.ResourceManagerControl) 'Control flags are retained'
    Assert (($null -eq $before.SystemAcl -and $null -eq $after.SystemAcl) -or ((Binary $before.SystemAcl) -ceq (Binary $after.SystemAcl))) 'Complete SACL bytes are retained'
    Assert ($after.DiscretionaryAcl.Count -eq $before.DiscretionaryAcl.Count + 1) 'Exactly one DACL ACE is added'
    $j = 0
    for ($i = 0; $i -lt $after.DiscretionaryAcl.Count; $i++) {
        if ($i -eq $plan.AddedAceIndex) {
            $ace = $after.DiscretionaryAcl[$i]
            Assert ($ace.SecurityIdentifier.Value -eq 'S-1-5-32-573' -and $ace.AccessMask -eq 1 -and $ace.AceFlags -eq 0 -and -not $ace.IsCallback) 'New ACE is precisely unconditional Event Log Readers read (no write/clear)'
        } else {
            Assert ((Binary $before.DiscretionaryAcl[$j]) -ceq (Binary $after.DiscretionaryAcl[$i])) 'Every preexisting ACE stays byte-identical and in order'
            $j++
        }
    }
    Assert ($plan.EffectiveReadAccess -eq 'Not tested') 'Structural grant does not prove effective token access'
    $second = Get-WelaChannelAccessPlan -SecurityDescriptor $plan.ProposedDescriptor
    Assert ($second.State -eq 'GrantPresent' -and -not $second.ProposedDescriptor) 'Repeated planning does not duplicate the ACE'
    Assert (Test-WelaChannelDescriptorEqual $plan.ProposedDescriptor $after.GetSddlForm('All')) 'Binary descriptor comparison handles Windows SDDL formatting'
    Assert (-not (Test-WelaChannelDescriptorEqual $Sddl $plan.ProposedDescriptor)) 'Descriptor comparison detects the added ACE'
}

Check-Preservation 'O:BAG:SYD:PAI(A;;0x7;;;BA)(A;;0x2;;;AU)(A;ID;0x1;;;SY)S:AI(AU;SAFA;0x1;;;WD)'
Check-Preservation 'O:BAG:SYD:(OA;;0x2;00112233-4455-6677-8899-aabbccddeeff;;AU)(A;;0x7;;;BA)'
Check-Preservation 'O:BAG:SYD:(A;;0x2;;;S-1-5-32-573)(A;;0x7;;;BA)'
foreach ($sddl in @('O:BAG:SYD:(A;;0x1;;;S-1-5-32-573)', 'O:BAG:SYD:(A;;0x7;;;S-1-5-32-573)')) {
    $result = Get-WelaChannelAccessPlan $sddl
    Assert ($result.State -eq 'GrantPresent' -and -not $result.ProposedDescriptor -and $result.EffectiveReadAccess -eq 'Not tested') 'Existing read/superset permission is preserved without claiming event access'
}
foreach ($sddl in @('', 'invalid', 'O:BAG:SY', 'O:BAG:SYD:NO_ACCESS_CONTROL', 'O:BAG:SYD:(D;;0x1;;;WD)(A;;0x7;;;BA)', 'O:BAG:SYD:(D;;GR;;;WD)(A;;0x7;;;BA)')) {
    $result = Get-WelaChannelAccessPlan $sddl
    Assert ($result.State -eq 'ManualReview' -and -not $result.ProposedDescriptor) 'Missing, invalid, null and denied descriptors refuse automatic modification'
}
# The original unknown ACE bytes must never be discarded. SDDL has no representation
# for arbitrary custom ACEs; parsing/planning must refuse instead of replacing them.
$raw = [System.Security.AccessControl.RawSecurityDescriptor]::new('O:BAG:SYD:(A;;0x7;;;BA)')
$raw.DiscretionaryAcl.InsertAce(1, [System.Security.AccessControl.CustomAce]::new(([Enum]::ToObject([System.Security.AccessControl.AceType], 127)), [System.Security.AccessControl.AceFlags]::None, [byte[]]@(0, 0, 0, 0)))
$binaryBefore = Binary $raw
$refused = $false
try {
    $sddl = $raw.GetSddlForm('All')
    $refused = (Get-WelaChannelAccessPlan $sddl).State -eq 'ManualReview'
} catch { $refused = $true }
Assert ($refused -and (Binary $raw) -ceq $binaryBefore) 'Unsupported unknown ACEs are retained and mutation is refused'

$profile = Get-WelaNativeChannelProfile
$before = @{}
foreach ($control in $profile.controls) { $before[$control.channel] = Get-WelaNativeChannel -Name $control.channel }
# Exercise actual CLI dispatch and JSON export using live Windows read APIs.
$out = Join-Path ([IO.Path]::GetTempPath()) ('wela-native-channel-live-' + [guid]::NewGuid().ToString('N') + '.json')
$shell = (Get-Process -Id $PID).Path
try {
    & $shell -NoProfile -File (Join-Path $repo 'WELA.ps1') channel-settings -ChannelAction Plan -GrantEventLogReaders -ResultsPath $out
    $cliExit = $LASTEXITCODE
    $report = Get-Content -LiteralPath $out -Raw -ErrorAction Stop | ConvertFrom-Json
    Assert ($cliExit -eq $report.ExitCode -and $cliExit -in @(0, 1)) 'Read-only CLI exit code agrees with its report (missing/unknown channels may return 1)'
    Assert ($report.Action -eq 'Plan' -and $report.QueryInventory.Count -eq 18 -and $report.ForwardingReadiness -eq 'Not verified') 'Real CLI plan exports channel inventory without a forwarding claim'
    Assert ($report.ExcludedQueries.Count -eq 2 -and @($report.QueryInventory | Where-Object { $_.Channel.Name -like '*Sysmon*' }).Count -eq 0) 'Live public output excludes non-native queries'
    foreach ($control in $profile.controls) {
        $first = $before[$control.channel]; $last = Get-WelaNativeChannel -Name $control.channel
        Assert ($first.State -eq $last.State -and $first.MaximumSizeInBytes -eq $last.MaximumSizeInBytes -and $first.LogMode -eq $last.LogMode -and $first.SecurityDescriptor -ceq $last.SecurityDescriptor) 'Live plan leaves channel metadata unchanged (or detects concurrent external drift)'
        $row = @($report.Controls | Where-Object { $_.Definition.channel -eq $control.channel })[0]
        Assert ($row.Before.MaximumSizeInBytes -eq $first.MaximumSizeInBytes -and $row.Before.SecurityDescriptor -ceq $first.SecurityDescriptor) 'Live exported metadata matches the actual native reader'
    }
    Write-Host "PASS: $script:assertions real Windows ACL and read-only CLI assertions. Identity access, event generation and forwarding were not tested."
    $global:LASTEXITCODE = 0 # A reported missing/manual-review channel is valid smoke evidence.
} finally { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
