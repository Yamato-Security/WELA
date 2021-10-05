# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "ParentImage.*.*\pcalua.exe" -or $_.message -match "ParentImage.*.*\forfiles.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_indirect_cmd";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_indirect_cmd";
            $detectedMessage = "Detect indirect command execution via Program Compatibility Assistant (pcalua.exe or forfiles.exe).";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "ParentImage.*.*\\pcalua.exe" -or $_.message -match "ParentImage.*.*\\forfiles.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
