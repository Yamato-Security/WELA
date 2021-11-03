# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "IntegrityLevel.*Medium" -and ($_.ID -eq "1") -and ($_.message -match "Product.*.*AccessChk" -or $_.message -match "Description.*.*Reports effective permissions")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_accesschk_usage_after_priv_escalation";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "sysmon_accesschk_usage_after_priv_escalation";
                    $detectedMessage = "Accesschk is an access and privilege audit tool developed by SysInternal and often being used by attacker to verify if a privilege escalation process succesfull or not ";
                $result = $event |  where {($_.ID -eq "1" -and $_.message -match "IntegrityLevel.*Medium" -and ($_.ID -eq "1") -and ($_.message -match "Product.*.*AccessChk" -or $_.message -match "Description.*.*Reports effective permissions")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
