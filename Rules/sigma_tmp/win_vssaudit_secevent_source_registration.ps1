# Get-WinEvent -LogName Security | where {($_.message -match "AuditSourceName.*VSSAudit" -and ($_.ID -eq "4904" -or $_.ID -eq "4905")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_vssaudit_secevent_source_registration";
    $detectedMessage = "Detects the registration of the security event source VSSAudit. It would usually trigger when volume shadow copy operations happen."

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.message -match "AuditSourceName.*VSSAudit" -and ($_.ID -eq "4904" -or $_.ID -eq "4905")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
