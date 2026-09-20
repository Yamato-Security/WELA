# Read-only native observations. Never configure rights, registry, tokens or audit exhaustion.
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') {throw 'This smoke test requires Windows.'}
$repo=Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/AuditIntegrity.ps1')
function Set-WelaIntegrityAccountRight {throw 'Native privilege mutation is forbidden in this read-only test.'}
function Set-ItemProperty {throw 'Registry mutation is forbidden in this read-only test.'}
$script:checks=0
function Assert($Value,[string]$Message) {if(-not $Value){throw "FAIL: $Message"};$script:checks++}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-integrity-readonly-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
try {
    $before=Get-WelaIntegritySnapshot
    Assert ($before.Errors.Count -eq 0) "Native LSA/CIM/registry observations succeed: $($before.Errors -join '; ')"
    Assert ($before.Host.Status -eq 'Known' -and $before.Rights.Count -eq 2) 'The actual host and both direct privilege assignments are observed'
    Assert ($before.Accounts.Count -ge 3 -and @($before.Accounts|Where-Object Status -ne 'Known').Count -eq 0) 'Affected accounts retain complete observed rights'
    $report=Invoke-WelaIntegrityCommand -ResultsPath (Join-Path $temp 'audit.json')
    Assert ($report.Action -eq 'Audit' -and $report.Plan.Operations.Count -eq 0 -and $report.SigmaEvtxCredit -eq 0) 'Default audit has no native operations or rule-coverage credit'
    $export=Get-Content -LiteralPath (Join-Path $temp 'audit.json') -Raw|ConvertFrom-Json
    Assert ($export.Scope -eq 'audit-integrity-local-policy-only' -and $export.Plan.Controls[0].SourceSetting -eq 'NoSourceSelected') 'Source requirements remain distinct from observed host policy in JSON'
    # Independent security-policy export; /export writes only the owned evidence files.
    $inf=Join-Path $temp 'rights.inf'
    $null=Invoke-WelaNative -FilePath (Join-Path $env:SystemRoot 'System32/secedit.exe') -Arguments @('/export','/cfg',$inf,'/areas','USER_RIGHTS','/log',(Join-Path $temp 'secedit.log'),'/quiet')
    $lines=@(Get-Content -LiteralPath $inf)
    foreach($right in @('SeAuditPrivilege','SeSecurityPrivilege')) {
        $matches=@($lines|Where-Object {$_ -match ('^'+[regex]::Escape($right)+'\s*=')})
        Assert ($matches.Count -le 1) 'Security-policy export has an unambiguous privilege entry'
        $sids=@()
        if($matches.Count) {
            $value=($matches[0] -split '=',2)[1].Trim()
            if($value) {
                foreach($name in ($value -split ',')) {
                    $name=$name.Trim().TrimStart('*')
                    if($name -match '^S-1-') {$sids+=@($name)}
                    else {$sids+=@(([Security.Principal.NTAccount]::new($name)).Translate([Security.Principal.SecurityIdentifier]).Value)}
                }
            }
        }
        $direct=@($before.Rights|Where-Object Name -eq $right)[0].Holders
        Assert ((@($sids|Sort-Object -Unique) -join '|') -ceq (@($direct|Sort-Object -Unique) -join '|')) "Native LSA $right assignment agrees with read-only secedit export"
    }
    $after=Get-WelaIntegritySnapshot
    Assert ((Get-WelaIntegrityStateKey $before) -ceq (Get-WelaIntegrityStateKey $after)) 'All observed rights, typed registry values and host state are unchanged'
    Write-Host "PASS: $script:checks native read-only audit-integrity assertions on $($before.Host.Role) build $($before.Host.Build). No privileges or Windows settings changed."
} finally {Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}
