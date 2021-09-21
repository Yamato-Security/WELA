# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "10" -and $_.message -match "CallTrace.*.*editionupgrademanagerobj.dll.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_load_undocumented_autoelevated_com_interface";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "sysmon_load_undocumented_autoelevated_com_interface";
                    $detectedMessage = "COM interface (EditionUpgradeManager) that is not used by standard executables.";
                $result = $event |  where {($_.ID -eq "10" -and $_.message -match "CallTrace.*.*editionupgrademanagerobj.dll.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
Write-Host $result;
Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
