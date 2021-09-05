# Get-WinEvent -LogName Security | where {($_.ID -eq "4719" -and ($_.message -match "AuditPolicyChanges.*.*%%8448.*" -or $_.message -match "AuditPolicyChanges.*.*%%8450.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_disable_event_logging";
    $detectedMessage = "!detection!"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "4719" -and ($_.message -match "AuditPolicyChanges.*.*%%8448.*" -or $_.message -match "AuditPolicyChanges.*.*%%8450.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
