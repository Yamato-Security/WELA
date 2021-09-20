# Get-WinEvent -LogName System | where {($_.message -match "Source.*Microsoft-Windows-Ntfs" -and $_.ID -eq "98" -and $_.message -match "DeviceName.*.*HarddiskVolumeShadowCopy.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_volume_shadow_copy_mount";
    $detectedMessage = "Detects volume shadow copy mount";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.message -match "Source.*Microsoft-Windows-Ntfs" -and $_.ID -eq "98" -and $_.message -match "DeviceName.*.*HarddiskVolumeShadowCopy.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
