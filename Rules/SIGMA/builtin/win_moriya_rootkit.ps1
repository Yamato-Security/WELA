# Get-WinEvent -LogName System | where {($_.ID -eq "7045" -and $_.message -match "ServiceName.*ZzNetSvc") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and $_.message -match "TargetFilename.*C:\\Windows\\System32\\drivers\\MoriyaStreamWatchmen.sys") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_moriya_rootkit";
    $detectedMessage = "Detects the use of Moriya rootkit as described in the securelist's Operation TunnelSnake report";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            $results = @();
            $results += $event | where { ($_.ID -eq "7045" -and $_.message -match "ServiceName.*ZzNetSvc") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.ID -eq "11" -and $_.message -match "TargetFilename.*C:\\Windows\\System32\\drivers\\MoriyaStreamWatchmen.sys") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            
            foreach ($result in $results) {
                if ($result.Count -ne 0) {
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $result
                    Write-Host $detectedMessage;    
                }
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
