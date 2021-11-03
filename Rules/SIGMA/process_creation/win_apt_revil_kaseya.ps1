# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*C:\Windows\cert.exe" -or $_.message -match "CommandLine.*.*Set-MpPreference -DisableRealtimeMonitoring $true -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled" -or $_.message -match "CommandLine.*.*del /q /f c:\kworking\agent.crt" -or $_.message -match "CommandLine.*.*Kaseya VSA Agent Hot-fix" -or $_.message -match "CommandLine.*.*\AppData\Local\Temp\MsMpEng.exe" -or $_.message -match "CommandLine.*.*rmdir /s /q %SystemDrive%\inetpub\logs" -or $_.message -match "CommandLine.*.*del /s /q /f %SystemDrive%\.*.log" -or $_.message -match "CommandLine.*.*c:\kworking1\agent.exe" -or $_.message -match "CommandLine.*.*c:\kworking1\agent.crt") -and ($_.message -match "C:\Windows\MsMpEng.exe" -or $_.message -match "C:\Windows\cert.exe" -or $_.message -match "C:\kworking\agent.exe" -or $_.message -match "C:\kworking1\agent.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_revil_kaseya";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_apt_revil_kaseya";
            $detectedMessage = "Detects process command line patterns and locations used by REvil group in Kaseya incident (can also match on other malware)";
            $result = $event | where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*C:\\Windows\\cert.exe" -or $_.message -match "CommandLine.*.*Set-MpPreference -DisableRealtimeMonitoring $true -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled" -or $_.message -match "CommandLine.*.*del /q /f c:\\kworking\\agent.crt" -or $_.message -match "CommandLine.*.*Kaseya VSA Agent Hot-fix" -or $_.message -match "CommandLine.*.*\\AppData\\Local\\Temp\\MsMpEng.exe" -or $_.message -match "CommandLine.*.*rmdir /s /q %SystemDrive%\\inetpub\\logs" -or $_.message -match "CommandLine.*.*del /s /q /f %SystemDrive%\\.*.log" -or $_.message -match "CommandLine.*.*c:\\kworking1\\agent.exe" -or $_.message -match "CommandLine.*.*c:\\kworking1\\agent.crt") -and ($_.message -match "C:\\Windows\\MsMpEng.exe" -or $_.message -match "C:\\Windows\\cert.exe" -or $_.message -match "C:\\kworking\\agent.exe" -or $_.message -match "C:\\kworking1\\agent.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result -and $result.Count -ne 0) {
                Write-Output ""; 
                Write-Output "Detected! RuleName:$ruleName";
                Write-Output $detectedMessage;
                Write-Output $result;
                Write-Output ""; 
            }
        };
        . Search-DetectableEvents $args;
    };
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
