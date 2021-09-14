# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "TargetObject.*.*\Security\Trusted Documents\TrustRecords" -or $_.message -match "TargetObject.*.*\Security\AccessVBOM" -or $_.message -match "TargetObject.*.*\Security\VBAWarnings")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_reg_office_security";
    $detectedMessage = "Detects registry changes to Office macro settings";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "TargetObject.*.*\Security\Trusted Documents\TrustRecords" -or $_.message -match "TargetObject.*.*\Security\AccessVBOM" -or $_.message -match "TargetObject.*.*\Security\VBAWarnings")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
