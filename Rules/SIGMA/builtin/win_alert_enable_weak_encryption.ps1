# Get-WinEvent -LogName Security | where {($_.ID -eq "4738" -and ($_.message -match ".*DES.*" -or $_.message -match ".*Preauth.*" -or $_.message -match ".*Encrypted.*") -and ($_.message -match ".*Enabled.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_alert_enable_weak_encryption";
    $detectedMessage = "Detects scenario where weak encryption is enabled for a user profile which could be used for hash/password cracking.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "4738" -and ($_.message -match ".*DES.*" -or $_.message -match ".*Preauth.*" -or $_.message -match ".*Encrypted.*") -and ($_.message -match ".*Enabled.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}
