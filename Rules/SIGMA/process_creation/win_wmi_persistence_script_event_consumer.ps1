# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*C:\\WINDOWS\\system32\\wbem\\scrcons.exe" -and $_.message -match "ParentImage.*C:\\Windows\\System32\\svchost.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_wmi_persistence_script_event_consumer";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_wmi_persistence_script_event_consumer";
            $detectedMessage = "Detects WMI script event consumers";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*C:\\WINDOWS\\system32\\wbem\\scrcons.exe" -and $_.message -match "ParentImage.*C:\\Windows\\System32\\svchost.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error" -Foreground Yellow;
    }
}
