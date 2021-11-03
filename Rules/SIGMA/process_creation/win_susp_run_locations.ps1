# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*:\\RECYCLER\\" -or $_.message -match "Image.*.*:\\SystemVolumeInformation\\") -or ($_.message -match "Image.*C:\\Windows\\Tasks\\" -or $_.message -match "Image.*C:\\Windows\\debug\\" -or $_.message -match "Image.*C:\\Windows\\fonts\\" -or $_.message -match "Image.*C:\\Windows\\help\\" -or $_.message -match "Image.*C:\\Windows\\drivers\\" -or $_.message -match "Image.*C:\\Windows\\addins\\" -or $_.message -match "Image.*C:\\Windows\\cursors\\" -or $_.message -match "Image.*C:\\Windows\\system32\\tasks\\"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_run_locations";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_run_locations";
            $detectedMessage = "Detects suspicious process run from unusual locations";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "Image.*.*:\\RECYCLER\\" -or $_.message -match "Image.*.*:\\SystemVolumeInformation\\") -or ($_.message -match "Image.*C:\\Windows\\Tasks\\" -or $_.message -match "Image.*C:\\Windows\\debug\\" -or $_.message -match "Image.*C:\\Windows\\fonts\\" -or $_.message -match "Image.*C:\\Windows\\help\\" -or $_.message -match "Image.*C:\\Windows\\drivers\\" -or $_.message -match "Image.*C:\\Windows\\addins\\" -or $_.message -match "Image.*C:\\Windows\\cursors\\" -or $_.message -match "Image.*C:\\Windows\\system32\\tasks\\"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
