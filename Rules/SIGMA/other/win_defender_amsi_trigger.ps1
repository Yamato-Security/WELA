# Get-WinEvent -LogName Microsoft-Windows-Windows Defender/Operational | where {($_.ID -eq "1116" -and $_.message -match "DetectionSource.*AMSI") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_defender_amsi_trigger";
    $detectedMessage = "Detects triggering of AMSI by Windows Defender.";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1116" -and $_.message -match "DetectionSource.*AMSI") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
