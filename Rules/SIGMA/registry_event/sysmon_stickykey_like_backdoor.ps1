# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\\Debugger" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\utilman.exe\\Debugger" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\osk.exe\\Debugger" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Magnify.exe\\Debugger" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Narrator.exe\\Debugger" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\DisplaySwitch.exe\\Debugger")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\\winlogon.exe" -and $_.message -match "Image.*.*\\cmd.exe" -and ($_.message -match "CommandLine.*.*sethc.exe.*" -or $_.message -match "CommandLine.*.*utilman.exe.*" -or $_.message -match "CommandLine.*.*osk.exe.*" -or $_.message -match "CommandLine.*.*Magnify.exe.*" -or $_.message -match "CommandLine.*.*Narrator.exe.*" -or $_.message -match "CommandLine.*.*DisplaySwitch.exe.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_stickykey_like_backdoor";
    $detectedMessage = "Detects the usage and installation of a backdoor that uses an option to register a malicious debugger for built-in tools that are accessible in the login";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $results = @();
            $results += $event | where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\\Debugger" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\utilman.exe\\Debugger" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\osk.exe\\Debugger" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Magnify.exe\\Debugger" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Narrator.exe\\Debugger" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\DisplaySwitch.exe\\Debugger")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\\winlogon.exe" -and $_.message -match "Image.*.*\\cmd.exe" -and ($_.message -match "CommandLine.*.*sethc.exe.*" -or $_.message -match "CommandLine.*.*utilman.exe.*" -or $_.message -match "CommandLine.*.*osk.exe.*" -or $_.message -match "CommandLine.*.*Magnify.exe.*" -or $_.message -match "CommandLine.*.*Narrator.exe.*" -or $_.message -match "CommandLine.*.*DisplaySwitch.exe.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            
            foreach ($result in $results) {
                if ($result.Count -ne 0) {
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $result
                    Write-Host $detectedMessage;    
                }
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}