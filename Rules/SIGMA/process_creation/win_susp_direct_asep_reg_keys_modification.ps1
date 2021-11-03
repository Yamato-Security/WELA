# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\reg.exe" -and $_.message -match "CommandLine.*.*add" -and ($_.message -match "CommandLine.*.*\\software\\Microsoft\\Windows\\CurrentVersion\\Run" -or $_.message -match "CommandLine.*.*\\software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" -or $_.message -match "CommandLine.*.*\\software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx" -or $_.message -match "CommandLine.*.*\\software\\Microsoft\\Windows\\CurrentVersion\\RunServices" -or $_.message -match "CommandLine.*.*\\software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce" -or $_.message -match "CommandLine.*.*\\software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit" -or $_.message -match "CommandLine.*.*\\software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" -or $_.message -match "CommandLine.*.*\\software\\Microsoft\\Windows NT\\CurrentVersion\\Windows" -or $_.message -match "CommandLine.*.*\\software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" -or $_.message -match "CommandLine.*.*\\system\\CurrentControlSet\\Control\\SafeBoot\\AlternateShell")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_direct_asep_reg_keys_modification";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_direct_asep_reg_keys_modification";
            $detectedMessage = "Detects direct modification of autostart extensibility point (ASEP) in registry using reg.exe.";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\reg.exe" -and $_.message -match "CommandLine.*.*add" -and ($_.message -match "CommandLine.*.*\\software\\Microsoft\\Windows\\CurrentVersion\\Run" -or $_.message -match "CommandLine.*.*\\software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" -or $_.message -match "CommandLine.*.*\\software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx" -or $_.message -match "CommandLine.*.*\\software\\Microsoft\\Windows\\CurrentVersion\\RunServices" -or $_.message -match "CommandLine.*.*\\software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce" -or $_.message -match "CommandLine.*.*\\software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit" -or $_.message -match "CommandLine.*.*\\software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" -or $_.message -match "CommandLine.*.*\\software\\Microsoft\\Windows NT\\CurrentVersion\\Windows" -or $_.message -match "CommandLine.*.*\\software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" -or $_.message -match "CommandLine.*.*\\system\\CurrentControlSet\\Control\\SafeBoot\\AlternateShell")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
