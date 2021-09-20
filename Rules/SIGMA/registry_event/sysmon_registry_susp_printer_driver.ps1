# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*.*\\Control\\Print\\Environments\\Windows x64\\Drivers.*" -and $_.message -match "TargetObject.*.*\\Manufacturer.*" -and $_.message -match "Details.*(Empty)") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_registry_susp_printer_driver";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "sysmon_registry_susp_printer_driver";
                    $detectedMessage = "Detects a suspicious printer driver installation with an empty Manufacturer value";
                $result = $event |  where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*.*\\Control\\Print\\Environments\\Windows x64\\Drivers.*" -and $_.message -match "TargetObject.*.*\\Manufacturer.*" -and $_.message -match "Details.*(Empty)") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
