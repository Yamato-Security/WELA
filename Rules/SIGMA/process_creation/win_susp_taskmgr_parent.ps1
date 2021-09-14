# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and $_.message -match "ParentImage.*.*\taskmgr.exe" -and  -not (($_.message -match "Image.*.*\resmon.exe" -or $_.message -match "Image.*.*\mmc.exe" -or $_.message -match "Image.*.*\taskmgr.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_taskmgr_parent";
    $detectedMessage = "Detects the creation of a process from Windows task manager";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and $_.message -match "ParentImage.*.*\taskmgr.exe" -and -not (($_.message -match "Image.*.*\resmon.exe" -or $_.message -match "Image.*.*\mmc.exe" -or $_.message -match "Image.*.*\taskmgr.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
