# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "10" -and $_.message -match "CallTrace.*.*editionupgrademanagerobj.dll") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_load_undocumented_autoelevated_com_interface";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "sysmon_load_undocumented_autoelevated_com_interface";
                    $detectedMessage = "COM interface (EditionUpgradeManager) that is not used by standard executables.";
                $result = $event |  where {($_.ID -eq "10" -and $_.message -match "CallTrace.*.*editionupgrademanagerobj.dll") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
