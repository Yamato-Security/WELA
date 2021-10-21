# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "EventType.*DeleteKey" -and ($_.message -match "TargetObject.*.*{2781761E-28E0-4109-99FE-B9D127C57AFE}" -or $_.message -match "TargetObject.*.*{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_removal_amsi_registry_key";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_removal_amsi_registry_key";
            $detectedMessage = "Remove the AMSI Provider registry key in HKLMSoftwareMicrosoftAMSI to disable AMSI inspection";
            $result = $event |  where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "EventType.*DeleteKey" -and ($_.message -match "TargetObject.*.*{2781761E-28E0-4109-99FE-B9D127C57AFE}" -or $_.message -match "TargetObject.*.*{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
