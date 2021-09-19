# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "EventType.*DeleteKey" -and ($_.message -match "TargetObject.*.*{2781761E-28E0-4109-99FE-B9D127C57AFE}" -or $_.message -match "TargetObject.*.*{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_removal_amsi_registry_key";
    $detectedMessage = "Remove the AMSI Provider registry key in HKLMSoftwareMicrosoftAMSI to disable AMSI inspection";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "EventType.*DeleteKey" -and ($_.message -match "TargetObject.*.*{2781761E-28E0-4109-99FE-B9D127C57AFE}" -or $_.message -match "TargetObject.*.*{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
