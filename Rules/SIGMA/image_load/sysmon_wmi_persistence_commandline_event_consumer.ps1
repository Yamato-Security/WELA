# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and $_.message -match "Image.*C:\Windows\System32\wbem\WmiPrvSE.exe" -and $_.message -match "ImageLoaded.*.*\wbemcons.dll") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_wmi_persistence_commandline_event_consumer";
    $detectedMessage = "Detects WMI command line event consumers";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "7" -and $_.message -match "Image.*C:\Windows\System32\wbem\WmiPrvSE.exe" -and $_.message -match "ImageLoaded.*.*\wbemcons.dll") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
