# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and (($_.message -match "TargetObject.*HKLM\\SYSTEM\\CurrentControlSet\\Control\\MiniNt" -and $_.message -match "EventType.*CreateKey") -or $_.message -match "NewName.*HKLM\\SYSTEM\\CurrentControlSet\\Control\\MiniNt")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_disable_security_events_logging_adding_reg_key_minint";
    $detectedMessage = "Detects the addition of a key 'MiniNt' to the registry. Upon a reboot, Windows Event Log service will stopped write events.";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and (($_.message -match "TargetObject.*HKLM\\SYSTEM\\CurrentControlSet\\Control\\MiniNt" -and $_.message -match "EventType.*CreateKey") -or $_.message -match "NewName.*HKLM\\SYSTEM\\CurrentControlSet\\Control\\MiniNt")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
