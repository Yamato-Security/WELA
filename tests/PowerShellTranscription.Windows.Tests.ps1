param([switch]$AllowDisposablePolicyWrite)
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { Write-Host 'Skipped: native Windows ACL/registry tests require Windows.'; exit 0 }
if ($AllowDisposablePolicyWrite -and ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted')) {
    throw 'Native policy mutation is restricted to this explicitly opted-in disposable GitHub-hosted runner test.'
}
$repo = Split-Path $PSScriptRoot -Parent
$script:ScriptRoot = $repo
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/PowerShellTranscription.ps1')
$script:checks = 0
function Assert($Condition, [string]$Message) { if (-not $Condition) { throw "FAIL: $Message" }; $script:checks++ }
$root = Join-Path ([IO.Path]::GetTempPath()) ('wela-native-transcription-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $root
$policyTouched = $false; $restored = $true; $before = $null
function Set-PrivateDirectoryAcl([string]$Path) {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.SetOwner($sid)
    foreach ($identity in @($sid.Value, 'S-1-5-18', 'S-1-5-32-544') | Select-Object -Unique) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($identity),
            [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Restore-OriginalPolicy($Policy) {
    $base = $null; $key = $null
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]([string]$Policy[0].View))
        $key = $base.CreateSubKey('SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription')
        # Stop new-session transcription while restoring the previous location.
        $key.SetValue('EnableTranscripting', 0, [Microsoft.Win32.RegistryValueKind]::DWord)
        foreach ($name in @('OutputDirectory', 'EnableTranscripting')) {
            $original = $Policy[0].Machine.$name
            if ($original.ValueExists) { $key.SetValue($name, $original.Value, [Microsoft.Win32.RegistryValueKind]([string]$original.Type)) }
            else { $key.DeleteValue($name, $false) }
        }
        $deleteEmptyKey = -not $Policy[0].Machine.EnableTranscripting.KeyExists -and $key.GetValueNames().Count -eq 0 -and $key.GetSubKeyNames().Count -eq 0
        $key.Dispose(); $key = $null
        if ($deleteEmptyKey) { $base.DeleteSubKey('SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription', $false) }
    } finally { if ($key) { $key.Dispose() }; if ($base) { $base.Dispose() } }
}
try {
    Set-PrivateDirectoryAcl $root
    $destination = Get-WelaTranscriptDestination $root
    Assert ($destination.ConfigureAllowed -and $destination.Status -eq 'Observed') 'actual private directory passes conservative ACL observations'
    Assert ($destination.Acl.Sddl -and $destination.WriterAuthorization -eq 'Unknown') 'SDDL is captured without claiming all writers have access'
    $unsafe = Join-Path $root 'unsafe-fixture'; $null = New-Item -ItemType Directory -Path $unsafe
    $unsafeAcl = Get-Acl -LiteralPath $unsafe
    $unsafeAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'),
        [Security.AccessControl.FileSystemRights]::ReadAndExecute, [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
        [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
    Set-Acl -LiteralPath $unsafe -AclObject $unsafeAcl
    $blocked = Get-WelaTranscriptDestination $unsafe
    Assert (-not $blocked.ConfigureAllowed -and $blocked.Status -eq 'Blocked' -and $blocked.Acl.Risks.Count -gt 0) 'actual broad-read ACL fixture is blocked'
    $missing = Get-WelaTranscriptDestination (Join-Path $root 'not-created')
    Assert (-not $missing.ConfigureAllowed -and $missing.Status -eq 'Unknown') 'missing destination never auto-created'
    $capability = Get-WelaTranscriptCapability
    Assert ($capability.Status -eq 'Supported') 'actual native Windows PowerShell 5.1 installation detected'
    $before = @(Get-WelaTranscriptPolicy $capability.Views)
    Test-WelaTranscriptSharedPolicy $before
    Assert ($before.Count -eq 2) 'actual Windows runner exposes shared 64/32 policy views'
    if ($AllowDisposablePolicyWrite) {
        $output = Join-Path $root 'transcripts'; $null = New-Item -ItemType Directory -Path $output
        $before | ConvertTo-Json -Depth 12 | Set-Content (Join-Path $root 'original-policy.json') -Encoding UTF8
        $policyTouched = $true; $restored = $false
        $report = Invoke-WelaTranscriptCommand -Action Configure -OutputDirectory $output -Auto -BackupPath (Join-Path $root 'backup')
        Assert ($report.ExitCode -eq 0 -and $report.Results[0].Status -eq 'Applied') 'actual policy writes and both-view readback succeed'
        $again = Invoke-WelaTranscriptCommand -Action Configure -OutputDirectory $output -Auto -BackupPath (Join-Path $root 'repeat-backup')
        Assert ($again.ExitCode -eq 0 -and $again.Results[0].Status -eq 'AlreadyCompliant') 'actual repeated policy configuration is idempotent'
        $executables = @((Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe'))
        $x86 = Join-Path $env:windir 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe'
        if (Test-Path -LiteralPath $x86 -PathType Leaf) { $executables += $x86 }
        foreach ($executable in $executables) {
            $marker = 'WELA-BENIGN-TRANSCRIPT-' + [guid]::NewGuid().ToString('N')
            $command = "if (`$PSVersionTable.PSVersion.Major -ne 5 -or `$PSVersionTable.PSVersion.Minor -ne 1) { exit 9 }; Write-Output '$marker'"
            $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
            $start = [Diagnostics.ProcessStartInfo]::new()
            $start.FileName = $executable; $start.Arguments = '-NoLogo -NoProfile -NonInteractive -EncodedCommand ' + $encoded
            $start.UseShellExecute = $false; $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
            $process = [Diagnostics.Process]::Start($start)
            try {
                if (-not $process.WaitForExit(30000)) { $process.Kill(); throw 'Benign Windows PowerShell child timed out.' }
                $childOutput = $process.StandardOutput.ReadToEnd(); $childError = $process.StandardError.ReadToEnd()
                Assert ($process.ExitCode -eq 0 -and $childOutput.Contains($marker)) "benign native 5.1 session succeeded: $executable; $childError"
            } finally { $process.Dispose() }
            $found = $false
            foreach ($file in @(Get-ChildItem -LiteralPath $output -Filter 'PowerShell_transcript*.txt' -Recurse -File)) {
                if ((Get-Content -LiteralPath $file.FullName -Raw).Contains($marker)) { $found = $true }
            }
            Assert $found 'policy-created transcript contains the benign marker without Start-Transcript in the child'
        }
        Assert ($report.Telemetry.SigmaEvtxCredit -eq 0) 'native text generation still provides no automatic Sigma EVTX credit'
    } else { Write-Host 'Native policy mutation skipped. Use the explicit disposable CI switch only on GitHub-hosted runners.' }
} finally {
    try {
        if ($policyTouched) {
            Restore-OriginalPolicy $before
            $after = @(Get-WelaTranscriptPolicy @($before.View))
            $restored = ($after | ConvertTo-Json -Depth 12 -Compress) -ceq ($before | ConvertTo-Json -Depth 12 -Compress)
            Assert $restored 'exact original machine/current-user values, types and policy-key presence restored'
        }
    } finally {
        if ($restored) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop }
        else { Write-Host "Policy restoration was not verified. Private evidence directory retained: $root" -ForegroundColor Red }
    }
}
Write-Host "Passed $script:checks Windows transcription assertions. Native policy was restored; fixtures were removed. UNC authorization and collection remain lab checks."
