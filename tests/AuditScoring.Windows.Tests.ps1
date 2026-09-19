# Read-only native integration. No policy writer, event generator, or restoration is used.
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'scripts/Configuration.ps1')
. (Join-Path $root 'scripts/ControlApplicability.ps1')
Import-Module (Join-Path $root 'modules/AuditProfiles.psm1') -Force
$script:count=0
function Assert($Condition,$Message) {if(-not $Condition){throw $Message};$script:count++}
function Policy-Fingerprint($Map) {(@($Map.Keys | Sort-Object | ForEach-Object {"$_=$($Map[$_])"}) -join ';')}
$before=Get-WelaEffectiveAuditPolicy
$beforeRegistry=Get-WelaRegistryState -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy
$beforePrecedence=$beforeRegistry | ConvertTo-Json -Compress
Assert ($before.Count -eq 59) 'All canonical native audit masks are readable.'
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-score-native-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
try {
    $json=Join-Path $temp 'score.json';$html=Join-Path $temp 'score.html'
    $exe=(Get-Process -Id $PID).Path
    # The public CLI must exercise ordinary helper scope on Windows 5.1 and 7.
    $ErrorActionPreference='Continue'
    try {$output=& $exe -NoProfile -File (Join-Path $root 'WELA.ps1') score -ScoreProfile wela-2.2.0 -ResultsPath $json -HtmlPath $html 2>&1;$code=$LASTEXITCODE}
    finally {$ErrorActionPreference='Stop'}
    Assert ($code -eq 0) ("Native score CLI failed ($code): " + ($output -join ' '))
    $report=Get-Content -LiteralPath $json -Raw | ConvertFrom-Json
    Assert ($report.Observation.Basis -eq 'Actual native Windows observation' -and $report.Observation.ComputerName -eq [Environment]::MachineName -and (Test-WelaDefaultContextComplete $report.Observation.Context)) 'Actual host identity and complete native context are retained.'
    $context=Get-WelaHostContext
    Assert ($report.ProfilePlan.role -eq $context.Role -and $report.ProfilePlan.build -eq $context.Build) 'Profile selection uses the real host role/build.'
    Assert ($report.Configuration.Denominator -gt 1 -and $report.Configuration.Unknown -eq 0 -and [string]::IsNullOrEmpty($report.Observation.Diagnostic)) 'Readable native masks are scored without hidden unknown reads.'
    $expectedPoints=0
    foreach($policy in $report.ProfilePlan.policies){
        if($policy.mode -notin @('exact','minimum') -or ($policy.mode -eq 'minimum' -and $policy.requiredMask -eq 0)){continue}
        $current=$before[$policy.guid]
        if(($policy.mode -eq 'minimum' -and ($current -band $policy.requiredMask) -eq $policy.requiredMask) -or ($policy.mode -eq 'exact' -and $current -eq $policy.requiredMask)){$expectedPoints++}
    }
    if($beforeRegistry.ValueExists -and $beforeRegistry.Type -eq 'DWord' -and $beforeRegistry.Value -eq 1){$expectedPoints++}
    Assert ($report.Configuration.Numerator -eq $expectedPoints) 'Reported configuration credit matches independently observed masks and typed precedence.'
    $parsed=Get-Content -LiteralPath (Join-Path $root 'config/security_rules.json') -Raw | ConvertFrom-Json
    $levels=@{};foreach($rule in $parsed){$levels[[string]$rule.id]=[string]$rule.level}
    $weights=@{critical=20;high=15;medium=10;low=5;informational=1};$denominator=0;$ids=@{}
    foreach($row in $report.Readiness.Rows){
        if($ids.ContainsKey($row.Id)){throw 'Duplicate scored rule ID'};$ids[$row.Id]=$true
        if($row.State -in @('Excluded','NotApplicable')){continue}
        $level=$levels[$row.Id].ToLowerInvariant()
        if($weights.ContainsKey($level)){$denominator+=$weights[$level]}else{$denominator++}
    }
    Assert ($report.Eligibility.Corpus.Pinned -and $ids.Count -eq $report.Eligibility.Corpus.Manifest.uniqueRuleCount -and $ids.Count -eq 2532) 'The full exact-byte corpus pin and all unique scored/excluded rule rows survive native CLI serialization.'
    Assert ($report.Readiness.Denominator -eq $denominator -and $denominator -gt 0 -and $report.Readiness.Numerator -eq 0 -and $report.Readiness.Ready -eq 0) 'Real settings alone earn no rule readiness; severity denominator matches the pinned metadata.'
    $rendered=[IO.File]::ReadAllText($html)
    Assert ($rendered -match [regex]::Escape([Environment]::MachineName) -and $rendered -match 'Observation UTC:' -and $rendered -match 'Detailed observed context' -and $rendered -notmatch '<script') 'Self-contained HTML exposes the native observation scope without executable content.'
    $jsonSize=(Get-Item -LiteralPath $json).Length;$htmlSize=(Get-Item -LiteralPath $html).Length
    Assert ($jsonSize -lt 20MB -and $htmlSize -lt 10MB) 'Full corpus reports stay within a bounded reviewable artifact size.'
    Write-Host "PASS: $script:count native scoring assertions; $($ids.Count) unique rules; JSON $jsonSize bytes / HTML $htmlSize bytes. No evidence or policy mutations."
} finally {
    $after=Get-WelaEffectiveAuditPolicy
    $afterPrecedence=Get-WelaRegistryState -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy | ConvertTo-Json -Compress
    Remove-Item -LiteralPath $temp -Recurse -Force
    if((Policy-Fingerprint $before) -cne (Policy-Fingerprint $after) -or $beforePrecedence -cne $afterPrecedence){throw 'Native policy/precedence changed during read-only scoring.'}
    Write-Host 'PASS: native audit masks and precedence are unchanged after scoring.'
}
$global:LASTEXITCODE=0
