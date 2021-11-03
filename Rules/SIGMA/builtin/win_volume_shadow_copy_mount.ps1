# Get-WinEvent -LogName System | where {($_.message -match "Source.*Microsoft-Windows-Ntfs" -and $_.ID -eq "98" -and $_.message -match "DeviceName.*.*HarddiskVolumeShadowCopy") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_volume_shadow_copy_mount";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_volume_shadow_copy_mount";
            $detectedMessage = "Detects volume shadow copy mount";
            $result = $event |  where { ($_.message -match "Source.*Microsoft-Windows-Ntfs" -and $_.ID -eq "98" -and $_.message -match "DeviceName.*.*HarddiskVolumeShadowCopy") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
