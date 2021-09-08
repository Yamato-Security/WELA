# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\sc.exe" -and $_.message -match "CommandLine.*.*create.*" -and $_.message -match "CommandLine.*.*binpath.*") -or ($_.message -match "Image.*.*\powershell.exe" -and $_.message -match "CommandLine.*.*new-service.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_new_service_creation";
    $detectedMessage = "Detects creation of a new service.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\sc.exe" -and $_.message -match "CommandLine.*.*create.*" -and $_.message -match "CommandLine.*.*binpath.*") -or ($_.message -match "Image.*.*\powershell.exe" -and $_.message -match "CommandLine.*.*new-service.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
