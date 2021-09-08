# Get-WinEvent -LogName System | where {($_.ID -eq "7045" -and $_.message -match "ServiceName.*ZzNetSvc") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and $_.message -match "TargetFilename.*C:\\Windows\\System32\\drivers\\MoriyaStreamWatchmen.sys") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_moriya_rootkit";
    $detectedMessage = "Detects the use of Moriya rootkit as described in the securelist's Operation TunnelSnake report";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "7045" -and $_.message -match "ServiceName.*ZzNetSvc") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $result2 = $event | where { ($_.ID -eq "11" -and $_.message -match "TargetFilename.*C:\\Windows\\System32\\drivers\\MoriyaStreamWatchmen.sys") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            ;
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
