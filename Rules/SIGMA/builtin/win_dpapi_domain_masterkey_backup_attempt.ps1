# Get-WinEvent -LogName Security | where {($_.ID -eq "4692") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_dpapi_domain_masterkey_backup_attempt";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_dpapi_domain_masterkey_backup_attempt";
            $detectedMessage = "Detects anyone attempting a backup for the DPAPI Master Key. This events gets generated at the source and not the Domain Controller.";
            $result = $event |  where { ($_.ID -eq "4692") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error" -Foreground Yellow;
    }
}
