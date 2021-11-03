# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*rundll32" -and (($_.message -match "CommandLine.*.*apphelp.dll" -and ($_.message -match "CommandLine.*.*ShimFlushCache" -or $_.message -match "CommandLine.*.*#250")) -or ($_.message -match "CommandLine.*.*kernel32.dll" -and ($_.message -match "CommandLine.*.*BaseFlushAppcompatCache" -or $_.message -match "CommandLine.*.*#46")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_shimcache_flush";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_shimcache_flush";
            $detectedMessage = "Detects actions that clear the local ShimCache and remove forensic evidence";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*rundll32" -and (($_.message -match "CommandLine.*.*apphelp.dll" -and ($_.message -match "CommandLine.*.*ShimFlushCache" -or $_.message -match "CommandLine.*.*#250")) -or ($_.message -match "CommandLine.*.*kernel32.dll" -and ($_.message -match "CommandLine.*.*BaseFlushAppcompatCache" -or $_.message -match "CommandLine.*.*#46")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
