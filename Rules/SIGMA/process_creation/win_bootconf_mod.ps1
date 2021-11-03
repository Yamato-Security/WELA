# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "Image.*.*\bcdedit.exe" -and $_.message -match "CommandLine.*.*set") -and (($_.message -match "CommandLine.*.*bootstatuspolicy" -and $_.message -match "CommandLine.*.*ignoreallfailures") -or ($_.message -match "CommandLine.*.*recoveryenabled" -and $_.message -match "CommandLine.*.*no"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_bootconf_mod";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_bootconf_mod";
            $detectedMessage = "Identifies use of the bcdedit command to delete boot configuration data. This tactic is sometimes used as by malware or an attacker as a destructive";
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "Image.*.*\\bcdedit.exe" -and $_.message -match "CommandLine.*.*set") -and (($_.message -match "CommandLine.*.*bootstatuspolicy" -and $_.message -match "CommandLine.*.*ignoreallfailures") -or ($_.message -match "CommandLine.*.*recoveryenabled" -and $_.message -match "CommandLine.*.*no"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
