# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "copy /y C:\windows\system32\cmd.exe C:\windows\system32\sethc.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_sticky_keys_unauthenticated_privileged_console_access";
    $detectedMessage = "By replacing the sticky keys executable with the local admins CMD executable, an attacker is able to access a privileged windows console session without authenticating to the system. When the sticky keys are ""activated"" the privilleged shell is launched.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "1" -and ($_.message -match "copy /y C:\windows\system32\cmd.exe C:\windows\system32\sethc.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
