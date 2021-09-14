# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "Image.*.*\bcdedit.exe" -and $_.message -match "CommandLine.*.*set.*") -and (($_.message -match "CommandLine.*.*bootstatuspolicy.*" -and $_.message -match "CommandLine.*.*ignoreallfailures.*") -or ($_.message -match "CommandLine.*.*recoveryenabled.*" -and $_.message -match "CommandLine.*.*no.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_bootconf_mod";
    $detectedMessage = "Identifies use of the bcdedit command to delete boot configuration data. This tactic is sometimes used as by malware or an attacker as a destructive";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and ($_.message -match "Image.*.*\bcdedit.exe" -and $_.message -match "CommandLine.*.*set.*") -and (($_.message -match "CommandLine.*.*bootstatuspolicy.*" -and $_.message -match "CommandLine.*.*ignoreallfailures.*") -or ($_.message -match "CommandLine.*.*recoveryenabled.*" -and $_.message -match "CommandLine.*.*no.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
