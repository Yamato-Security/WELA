# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "EventType.*CreateKey" -and $_.message -match "TargetObject.*.*HKU\\" -and $_.message -match "TargetObject.*.*_Classes\\CLSID\\" -and $_.message -match "TargetObject.*.*\\TreatAs") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_registry_persistence_key_linking";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_registry_persistence_key_linking";
            $detectedMessage = "Detects COM object hijacking via TreatAs subkey";
            $result = $event |  where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "EventType.*CreateKey" -and $_.message -match "TargetObject.*.*HKU\\" -and $_.message -match "TargetObject.*.*_Classes\\CLSID\\" -and $_.message -match "TargetObject.*.*\\TreatAs") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
