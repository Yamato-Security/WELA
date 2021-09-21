# Get-WinEvent -LogName Security | where {($_.ID -eq "4624" -and $_.message -match "LogonType.*3" -and $_.message -match "TargetUserName.*ANONYMOUS_LOGON" -and $_.message -match "WorkstationName.*-" -and $_.message -match "IpAddress.*127.0.0.1") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_rottenpotato";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_rottenpotato";
            $detectedMessage = "Detects logon events that have characteristics of events generated during an attack with RottenPotato and the like";
            $result = $event |  where { ($_.ID -eq "4624" -and $_.message -match "LogonType.*3" -and $_.message -match "TargetUserName.*ANONYMOUS_LOGON" -and $_.message -match "WorkstationName.*-" -and $_.message -match "IpAddress.*127.0.0.1") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
