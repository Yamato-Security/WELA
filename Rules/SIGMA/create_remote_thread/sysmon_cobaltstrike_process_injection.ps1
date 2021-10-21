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
