# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "8" -and ($_.message -match "TargetProcessAddress.*.*0B80" -or $_.message -match "TargetProcessAddress.*.*0C7C" -or $_.message -match "TargetProcessAddress.*.*0C88")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_cobaltstrike_process_injection";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_cobaltstrike_process_injection";
            $detectedMessage = "Detects a possible remote threat creation with certain characteristics which are typical for Cobalt Strike beacons";
            $result = $event |  where { ($_.ID -eq "8" -and ($_.message -match "TargetProcessAddress.*.*0B80" -or $_.message -match "TargetProcessAddress.*.*0C7C" -or $_.message -match "TargetProcessAddress.*.*0C88")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    $ruleStack.Add($ruleName, $detectRule);
}
