# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and (($_.message -match "TargetObject.*HKLM\\SYSTEM\\CurrentControlSet\\Control\\MiniNt" -and $_.message -match "EventType.*CreateKey") -or $_.message -match "NewName.*HKLM\\SYSTEM\\CurrentControlSet\\Control\\MiniNt")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_disable_security_events_logging_adding_reg_key_minint";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_disable_security_events_logging_adding_reg_key_minint";
            $detectedMessage = "Detects the addition of a key 'MiniNt' to the registry. Upon a reboot, Windows Event Log service will stopped write events.";
            $result = $event |  where { ((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and (($_.message -match "TargetObject.*HKLM\\SYSTEM\\CurrentControlSet\\Control\\MiniNt" -and $_.message -match "EventType.*CreateKey") -or $_.message -match "NewName.*HKLM\\SYSTEM\\CurrentControlSet\\Control\\MiniNt")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
