# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ((($_.message -match "ParentImage.*.*\wmiprvse.exe") -and ($_.message -match "Image.*.*\powershell.exe")) -and  -not ($_.message -match "CommandLine.*null")) -and  -not (-not CommandLine="*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_wmi_spwns_powershell";
    $detectedMessage = "Detects WMI spawning PowerShell"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and ((($_.message -match "ParentImage.*.*\wmiprvse.exe") -and ($_.message -match "Image.*.*\powershell.exe")) -and -not ($_.message -match "CommandLine.*null")) -and -not (-not CommandLine="*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
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