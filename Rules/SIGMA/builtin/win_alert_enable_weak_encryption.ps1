# Get-WinEvent -LogName Security | where {($_.ID -eq "4738" -and ($_.message -match "DES" -or $_.message -match "Preauth" -or $_.message -match "Encrypted") -and ($_.message -match "Enabled")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_alert_enable_weak_encryption";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_alert_enable_weak_encryption";
            $detectedMessage = "Detects scenario where weak encryption is enabled for a user profile which could be used for hash/password cracking.";
            $result = $event |  where { ($_.ID -eq "4738" -and ($_.message -match "DES" -or $_.message -match "Preauth" -or $_.message -match "Encrypted") -and ($_.message -match "Enabled")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
