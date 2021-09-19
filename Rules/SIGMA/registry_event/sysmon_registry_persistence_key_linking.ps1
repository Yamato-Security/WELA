# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "EventType.*CreateKey" -and $_.message -match "TargetObject.*.*HKU\.*" -and $_.message -match "TargetObject.*.*_Classes\CLSID\.*" -and $_.message -match "TargetObject.*.*\TreatAs.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_registry_persistence_key_linking";
    $detectedMessage = "Detects COM object hijacking via TreatAs subkey";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "EventType.*CreateKey" -and $_.message -match "TargetObject.*.*HKU\.*" -and $_.message -match "TargetObject.*.*_Classes\CLSID\.*" -and $_.message -match "TargetObject.*.*\TreatAs.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
