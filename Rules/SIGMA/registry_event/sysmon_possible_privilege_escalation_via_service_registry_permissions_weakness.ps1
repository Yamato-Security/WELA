# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "IntegrityLevel.*Medium" -and $_.message -match "TargetObject.*.*\services\.*" -and ($_.message -match "TargetObject.*.*\ImagePath" -or $_.message -match "TargetObject.*.*\FailureCommand" -or $_.message -match "TargetObject.*.*\Parameters\ServiceDll")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_possible_privilege_escalation_via_service_registry_permissions_weakness";
    $detectedMessage = "Detect modification of services configuration (ImagePath, FailureCommand and ServiceDLL) in registry by processes with Medium integrity level";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "IntegrityLevel.*Medium" -and $_.message -match "TargetObject.*.*\services\.*" -and ($_.message -match "TargetObject.*.*\ImagePath" -or $_.message -match "TargetObject.*.*\FailureCommand" -or $_.message -match "TargetObject.*.*\Parameters\ServiceDll")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
