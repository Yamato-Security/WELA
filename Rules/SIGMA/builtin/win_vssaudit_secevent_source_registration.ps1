# Get-WinEvent -LogName Security | where {($_.message -match "AuditSourceName.*VSSAudit" -and ($_.ID -eq "4904" -or $_.ID -eq "4905")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_vssaudit_secevent_source_registration";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_vssaudit_secevent_source_registration";
            $detectedMessage = "Detects the registration of the security event source VSSAudit. It would usually trigger when volume shadow copy operations happen.";
            $result = $event |  where { ($_.message -match "AuditSourceName.*VSSAudit" -and ($_.ID -eq "4904" -or $_.ID -eq "4905")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
