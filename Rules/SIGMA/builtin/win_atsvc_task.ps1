# Get-WinEvent -LogName Security | where {($_.ID -eq "5145" -and $_.message -match "ShareName.*\.*\IPC$" -and $_.message -match "RelativeTargetName.*atsvc" -and $_.message -match "Accesses.*.*WriteData.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_atsvc_task";
    $detectedMessage = "Detects remote task creation via at.exe or API interacting with ATSVC namedpipe";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "5145" -and $_.message -match "ShareName.*\.*\IPC$" -and $_.message -match "RelativeTargetName.*atsvc" -and $_.message -match "Accesses.*.*WriteData.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
