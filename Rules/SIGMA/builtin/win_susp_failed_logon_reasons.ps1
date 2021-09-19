# Get-WinEvent -LogName Security | where {(($_.ID -eq "4625" -or $_.ID -eq "4776") -and ($_.message -match "0xC0000072" -or $_.message -match "0xC000006F" -or $_.message -match "0xC0000070" -or $_.message -match "0xC0000413" -or $_.message -match "0xC000018C" -or $_.message -match "0xC000015B")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_failed_logon_reasons";
    $detectedMessage = "This method uses uncommon error codes on failed logons to determine suspicious activity and tampering with accounts that have been disabled or somehow";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "4625" -or $_.ID -eq "4776") -and ($_.message -match "0xC0000072" -or $_.message -match "0xC000006F" -or $_.message -match "0xC0000070" -or $_.message -match "0xC0000413" -or $_.message -match "0xC000018C" -or $_.message -match "0xC000015B")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
