# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "TargetObject.*.*Software\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility\\ATs" -or $_.message -match "TargetObject.*.*Software\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility\\Configuration")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_atbroker_change";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_susp_atbroker_change";
            $result = $event |  where { ((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "TargetObject.*.*Software\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility\\ATs" -or $_.message -match "TargetObject.*.*Software\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility\\Configuration")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
