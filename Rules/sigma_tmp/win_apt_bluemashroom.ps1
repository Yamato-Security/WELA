# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*\AppData\Local\.*" -and ($_.message -match "CommandLine.*.*\regsvr32.*" -or $_.message -match "CommandLine.*.*,DllEntry.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_apt_bluemashroom";
    $detectedMessage = "Detects a suspicious DLL loading from AppData Local path as described in BlueMashroom report"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*\AppData\Local\.*" -and ($_.message -match "CommandLine.*.*\regsvr32.*" -or $_.message -match "CommandLine.*.*,DllEntry.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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