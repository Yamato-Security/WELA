# Get-WinEvent | where {($_.ID -eq "1121" -and $_.message -match "Path.*.*\lsass.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_alert_lsass_access";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_alert_lsass_access";
            $detectedMessage = "Detects Access to LSASS Process";
            $result = $event |  where { ($_.ID -eq "1121" -and $_.message -match "Path.*.*\\lsass.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
