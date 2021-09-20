# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "IntegrityLevel.*Medium" -and ($_.ID -eq "1") -and ($_.message -match "Product.*.*AccessChk" -or $_.message -match "Description.*.*Reports effective permissions.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_accesschk_usage_after_priv_escalation";
    $detectedMessage = "Accesschk is an access and privilege audit tool developed by SysInternal and often being used by attacker to verify if a privilege escalation process succesfull or not ";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "IntegrityLevel.*Medium" -and ($_.ID -eq "1") -and ($_.message -match "Product.*.*AccessChk" -or $_.message -match "Description.*.*Reports effective permissions.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
