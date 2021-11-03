# Get-WinEvent -LogName Security | where {(($_.ID -eq "4625" -or $_.ID -eq "4776") -and ($_.message -match "0xC0000072" -or $_.message -match "0xC000006F" -or $_.message -match "0xC0000070" -or $_.message -match "0xC0000413" -or $_.message -match "0xC000018C" -or $_.message -match "0xC000015B")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_failed_logon_reasons";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_failed_logon_reasons";
            $detectedMessage = "This method uses uncommon error codes on failed logons to determine suspicious activity and tampering with accounts that have been disabled or somehow";
            $result = $event |  where { (($_.ID -eq "4625" -or $_.ID -eq "4776") -and ($_.message -match "0xC0000072" -or $_.message -match "0xC000006F" -or $_.message -match "0xC0000070" -or $_.message -match "0xC0000413" -or $_.message -match "0xC000018C" -or $_.message -match "0xC000015B")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
