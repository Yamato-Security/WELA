# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*C:\Windows\cert.exe.*" -or $_.message -match "CommandLine.*.*Set-MpPreference -DisableRealtimeMonitoring $true -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled.*" -or $_.message -match "CommandLine.*.*del /q /f c:\kworking\agent.crt.*" -or $_.message -match "CommandLine.*.*Kaseya VSA Agent Hot-fix.*" -or $_.message -match "CommandLine.*.*\AppData\Local\Temp\MsMpEng.exe.*" -or $_.message -match "CommandLine.*.*rmdir /s /q %SystemDrive%\inetpub\logs.*" -or $_.message -match "CommandLine.*.*del /s /q /f %SystemDrive%\.*.log.*" -or $_.message -match "CommandLine.*.*c:\kworking1\agent.exe.*" -or $_.message -match "CommandLine.*.*c:\kworking1\agent.crt.*") -and ($_.message -match "C:\Windows\MsMpEng.exe" -or $_.message -match "C:\Windows\cert.exe" -or $_.message -match "C:\kworking\agent.exe" -or $_.message -match "C:\kworking1\agent.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_revil_kaseya";
    $detectedMessage = "Detects process command line patterns and locations used by REvil group in Kaseya incident (can also match on other malware)";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*C:\Windows\cert.exe.*" -or $_.message -match "CommandLine.*.*Set-MpPreference -DisableRealtimeMonitoring $true -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled.*" -or $_.message -match "CommandLine.*.*del /q /f c:\kworking\agent.crt.*" -or $_.message -match "CommandLine.*.*Kaseya VSA Agent Hot-fix.*" -or $_.message -match "CommandLine.*.*\AppData\Local\Temp\MsMpEng.exe.*" -or $_.message -match "CommandLine.*.*rmdir /s /q %SystemDrive%\inetpub\logs.*" -or $_.message -match "CommandLine.*.*del /s /q /f %SystemDrive%\.*.log.*" -or $_.message -match "CommandLine.*.*c:\kworking1\agent.exe.*" -or $_.message -match "CommandLine.*.*c:\kworking1\agent.crt.*") -and ($_.message -match "C:\Windows\MsMpEng.exe" -or $_.message -match "C:\Windows\cert.exe" -or $_.message -match "C:\kworking\agent.exe" -or $_.message -match "C:\kworking1\agent.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
