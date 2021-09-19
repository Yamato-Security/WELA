# Get-WinEvent -LogName Security | where {($_.ID -eq "5145" -and $_.message -match "ShareName.*\.*\SYSVOL" -and $_.message -match "RelativeTargetName.*.*ScheduledTasks.xml" -and ($_.message -match "Accesses.*.*WriteData.*" -or $_.message -match "Accesses.*.*%%4417.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_GPO_scheduledtasks";
    $detectedMessage = "Detect lateral movement using GPO scheduled task, usually used to deploy ransomware at scale";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "5145" -and $_.message -match "ShareName.*\.*\SYSVOL" -and $_.message -match "RelativeTargetName.*.*ScheduledTasks.xml" -and ($_.message -match "Accesses.*.*WriteData.*" -or $_.message -match "Accesses.*.*%%4417.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
