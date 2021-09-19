# Get-WinEvent -LogName Security | where {(($_.ID -eq "4720" -or $_.ID -eq "4781") -and $_.message -match "SamAccountName.*.*$.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_new_or_renamed_user_account_with_dollar_sign";
    $detectedMessage = "Detects possible bypass EDR and SIEM via abnormal user account name.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "4720" -or $_.ID -eq "4781") -and $_.message -match "SamAccountName.*.*$.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
