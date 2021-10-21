# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and $_.message -match "Image.*C:\Windows\System32\wbem\WmiPrvSE.exe" -and $_.message -match "ImageLoaded.*.*\wbemcons.dll") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_wmi_persistence_commandline_event_consumer";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_wmi_persistence_commandline_event_consumer";
            $detectedMessage = "Detects WMI command line event consumers";
            $result = $event |  where { ($_.ID -eq "7" -and $_.message -match "Image.*C:\\Windows\\System32\\wbem\\WmiPrvSE.exe" -and $_.message -match "ImageLoaded.*.*\\wbemcons.dll") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
