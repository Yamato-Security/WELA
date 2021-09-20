# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*:\Users\.*" -and $_.message -match "TargetFilename.*.*\.config\rclone\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_rclone_exec_file";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_rclone_exec_file";
            $detectedMessage = "Detects Rclone config file being created";
            $result = $event |  where { ($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*:\\Users\\.*" -and $_.message -match "TargetFilename.*.*\\.config\\rclone\\.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
