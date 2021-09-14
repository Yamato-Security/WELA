# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\mshta.exe" -and ($_.message -match "Image.*.*\powershell.exe" -or $_.message -match "Image.*.*\cmd.exe" -or $_.message -match "Image.*.*\WScript.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_shell_spawn_mshta";
    $detectedMessage = "Detects a suspicious child process of a mshta.exe process";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\mshta.exe" -and ($_.message -match "Image.*.*\powershell.exe" -or $_.message -match "Image.*.*\cmd.exe" -or $_.message -match "Image.*.*\WScript.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
