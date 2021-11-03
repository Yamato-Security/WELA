# Get-WinEvent -LogName Security | where {($_.ID -eq "5145" -and $_.message -match "ShareName.*\.*\SYSVOL" -and $_.message -match "RelativeTargetName.*.*ScheduledTasks.xml" -and ($_.message -match "Accesses.*.*WriteData" -or $_.message -match "Accesses.*.*%%4417")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_GPO_scheduledtasks";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_GPO_scheduledtasks";
            $detectedMessage = "Detect lateral movement using GPO scheduled task, usually used to deploy ransomware at scale";
            $result = $event |  where { ($_.ID -eq "5145" -and $_.message -match "ShareName.*\\.*\\SYSVOL" -and $_.message -match "RelativeTargetName.*.*ScheduledTasks.xml" -and ($_.message -match "Accesses.*.*WriteData" -or $_.message -match "Accesses.*.*%%4417")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
