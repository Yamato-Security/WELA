# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*.*\\Software\\Sysinternals\\SDelete") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_sysinternals_sdelete_registry_keys";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_sysinternals_sdelete_registry_keys";
            $detectedMessage = "A General detection to trigger for the creation or modification of .*SoftwareSysinternalsSDelete registry keys. Indicators of the use of Sysinternals SDelete tool.";
            $result = $event |  where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*.*\\Software\\Sysinternals\\SDelete") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
