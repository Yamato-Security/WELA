param([string]$OutputDirectory = (Join-Path ([IO.Path]::GetTempPath()) ('wela-native-smoke-' + [guid]::NewGuid().ToString('N'))))
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'This read-only smoke test requires Windows.' }
$null = New-Item -ItemType Directory -Path $OutputDirectory -Force
# Loading version defines the actual public audit path without configuring Windows.
. (Join-Path $PSScriptRoot '../WELA.ps1') -Cmd version
$script:ScriptRoot = $OutputDirectory
$script:AuditpolTxtPath = Join-Path $OutputDirectory 'auditpol.txt'
$json = Join-Path $OutputDirectory 'native-assessment.json'
$html = Join-Path $OutputDirectory 'native-assessment.html'
$null = AuditLogSetting -outType table -Baseline Microsoft_Server -ResultsPath $json -HtmlPath $html
if (-not (Test-Path -LiteralPath $json)) { throw 'The public audit command did not export an assessment.' }
$report = Get-Content -LiteralPath $json -Raw | ConvertFrom-Json
$sources = @($report.Results | ForEach-Object { $_.NativeSources })
$application = @($sources | Where-Object { $_.Channel.Name -eq 'Application' })
if ($application.Count -ne 1) { throw 'Expected exactly one Application channel observation.' }
$actual = Get-WinEvent -ListLog Application -ErrorAction Stop
if ($application[0].Channel.IsEnabled -ne $actual.IsEnabled -or
    $application[0].Channel.LogMode -ne [string]$actual.LogMode -or
    $application[0].Channel.SecurityDescriptor -ne $actual.SecurityDescriptor) {
    throw 'Application channel evidence does not match the native read-only API.'
}
if (@($sources | Where-Object { $_.Provider.EventGenerationVerified -ne $false -or $_.RuleCoverage -ne 'Unconfirmed' }).Count) {
    throw 'Read-only channel observations must not claim validated event generation.'
}
$missing = Get-WelaNativeChannel -Name ('WELA-Not-Registered-' + [guid]::NewGuid().ToString('N'))
if ($missing.State -ne 'Not installed' -or -not $missing.Error) { throw 'A missing real Windows channel must retain its absent-registration evidence.' }
Write-Host "PASS: real Windows channel metadata, absent-channel classification and public JSON/HTML export. Evidence: $OutputDirectory"
Write-Host 'This smoke test does not validate event generation on Windows 11, domain controllers or AD CS, nor central ingestion.'
