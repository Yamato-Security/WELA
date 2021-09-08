# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\rundll32.exe") -and ($_.message -match "CommandLine.*.*,RunDLL")) -and  -not (($_.message -match "ParentImage.*.*\tracker.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_emotet_rudll32_execution";
    $detectedMessage = "Detecting Emotet DLL loading by looking for rundll32.exe processes with command lines ending in ,RunDLL or ,#1";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\rundll32.exe") -and ($_.message -match "CommandLine.*.*,RunDLL")) -and -not (($_.message -match "ParentImage.*.*\tracker.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
