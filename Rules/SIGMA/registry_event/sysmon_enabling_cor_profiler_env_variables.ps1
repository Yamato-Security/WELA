# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "TargetObject.*.*\\COR_ENABLE_PROFILING" -or $_.message -match "TargetObject.*.*\\COR_PROFILER")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_enabling_cor_profiler_env_variables";
    $detectedMessage = "This rule detects cor_enable_profiling and cor_profiler environment variables being set and configured.";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "TargetObject.*.*\\COR_ENABLE_PROFILING" -or $_.message -match "TargetObject.*.*\\COR_PROFILER")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
