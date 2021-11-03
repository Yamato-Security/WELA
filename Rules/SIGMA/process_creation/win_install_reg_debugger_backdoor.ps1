# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*\CurrentVersion\Image File Execution Options\" -and ($_.message -match "CommandLine.*.*sethc.exe" -or $_.message -match "CommandLine.*.*utilman.exe" -or $_.message -match "CommandLine.*.*osk.exe" -or $_.message -match "CommandLine.*.*magnify.exe" -or $_.message -match "CommandLine.*.*narrator.exe" -or $_.message -match "CommandLine.*.*displayswitch.exe" -or $_.message -match "CommandLine.*.*atbroker.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_install_reg_debugger_backdoor";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_install_reg_debugger_backdoor";
            $detectedMessage = "Detects the registration of a debugger for a program that is available in the logon screen (sticky key backdoor).";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*\\CurrentVersion\\Image File Execution Options\\" -and ($_.message -match "CommandLine.*.*sethc.exe" -or $_.message -match "CommandLine.*.*utilman.exe" -or $_.message -match "CommandLine.*.*osk.exe" -or $_.message -match "CommandLine.*.*magnify.exe" -or $_.message -match "CommandLine.*.*narrator.exe" -or $_.message -match "CommandLine.*.*displayswitch.exe" -or $_.message -match "CommandLine.*.*atbroker.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
