$ErrorActionPreference='Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Windows required.' }
. (Join-Path $PSScriptRoot '../scripts/AppLockerReadiness.ps1')
$report=Get-WelaAppLockerReadiness
if ($report.Collections.Count -ne 5 -or $report.CspPolicyState -ne 'Unknown' -or $report.UsableRuleCredit -ne 0) { throw 'Native report lost collection/CSP uncertainty.' }
if ($report.Host.Status -eq 'Unknown') { throw ($report.Host | ConvertTo-Json) }
foreach ($scope in @($report.LocalPolicy,$report.EffectiveGpPolicy)) {
    if ($scope.Status -eq 'Observed' -and -not $scope.Policy.Xml) { throw 'Observed policy must retain XML evidence.' }
    if ($scope.Status -ne 'Observed') { Write-Host "Policy read limitation: $($scope.Status) $($scope.Diagnostic)" }
}
# The native cmdlet parses the XML without installing it or executing the file.
if (Get-Command Test-AppLockerPolicy -ErrorAction SilentlyContinue) {
    $path=Join-Path $env:TEMP ('wela-applocker-schema-'+[guid]::NewGuid().ToString('N')+'.xml')
    try {
        $xml='<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="AuditOnly"><FilePathRule Id="12345678-1234-1234-1234-123456789abc" Name="Read-only test" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions></FilePathRule></RuleCollection></AppLockerPolicy>'
        $policy=ConvertFrom-WelaAppLockerXml -Xml $xml -ForImport
        $lock=New-WelaAppLockerImportReadLock -Path $path -Xml $policy.Xml
        try {
            $validation=@(Test-AppLockerPolicy -XmlPolicy $path -Path "$env:SystemRoot\System32\cmd.exe" -User 'S-1-1-0' -ErrorAction Stop)
            if (-not $validation.Count) { throw 'Native schema validation returned no decision.' }
        } finally { $lock.Dispose() }
    } finally { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
} else { Write-Host 'Native policy validation unavailable in this PowerShell session; importer will refuse.' }
Write-Host 'PASS: native read-only AppLocker observations. No Set-AppLockerPolicy or service changes.'
