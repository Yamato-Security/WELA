# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "IntegrityLevel.*Medium" -and $_.message -match "TargetObject.*.*\\services\\" -and ($_.message -match "TargetObject.*.*\\ImagePath" -or $_.message -match "TargetObject.*.*\\FailureCommand" -or $_.message -match "TargetObject.*.*\\Parameters\\ServiceDll")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_possible_privilege_escalation_via_service_registry_permissions_weakness";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_possible_privilege_escalation_via_service_registry_permissions_weakness";
            $detectedMessage = "Detect modification of services configuration (ImagePath, FailureCommand and ServiceDLL) in registry by processes with Medium integrity level";
            $result = $event |  where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "IntegrityLevel.*Medium" -and $_.message -match "TargetObject.*.*\\services\\" -and ($_.message -match "TargetObject.*.*\\ImagePath" -or $_.message -match "TargetObject.*.*\\FailureCommand" -or $_.message -match "TargetObject.*.*\\Parameters\\ServiceDll")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
