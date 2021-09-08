# Get-WinEvent -LogName System | where {($_.ID -eq "7045" -and ($_.Service File Name -eq "*\\PAExec*" -or $_.message -match "ServiceName.*mssecsvc2.0" -or $_.Service File Name -eq "*net user*" -or $_.message -match "ServiceName.*Java(TM) Virtual Machine Support Service")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Security | where {($_.ID -eq "4697" -and $_.message -match "ServiceName.*javamtsup") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_mal_service_installs";
    $detectedMessage = "Detects known malicious service installs that only appear in cases of lateral movement, credential dumping, and other suspicious activities.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "7045" -and ($_.message -match "*\\PAExec*" -or $_.message -match "ServiceName.*mssecsvc2.0" -or $_.message -match "*net user*" -or $_.message -match "ServiceName.*Java(TM) Virtual Machine Support Service")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $result2 = $event | where { ($_.ID -eq "4697" -and $_.message -match "ServiceName.*javamtsup") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            
            if (($result.Count -ne 0) -or ($result2.Count -ne 0)) {
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
