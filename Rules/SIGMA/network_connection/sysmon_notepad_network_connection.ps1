# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "3") -and $_.message -match "Image.*.*\notepad.exe" -and  -not ($_.message -match "DestinationPort.*9100")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_notepad_network_connection";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "sysmon_notepad_network_connection";
                    $detectedMessage = "Detects suspicious network connection by Notepad";
                $result = $event |  where { (($_.ID -eq "3") -and $_.message -match "Image.*.*\\notepad.exe" -and -not ($_.message -match "DestinationPort.*9100")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
