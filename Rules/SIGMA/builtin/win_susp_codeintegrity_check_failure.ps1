# Get-WinEvent -LogName Security | where {(($_.ID -eq "5038" -or $_.ID -eq "6281")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_codeintegrity_check_failure";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_codeintegrity_check_failure";
            $detectedMessage = "Code integrity failures may indicate tampered executables.";
            $result = $event |  where { (($_.ID -eq "5038" -or $_.ID -eq "6281")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    $ruleStack.Add($ruleName, $detectRule);
}
