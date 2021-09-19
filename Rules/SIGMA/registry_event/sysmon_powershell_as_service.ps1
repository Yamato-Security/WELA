# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*.*\Services\.*" -and $_.message -match "TargetObject.*.*\ImagePath" -and ($_.message -match "Details.*.*powershell.*" -or $_.message -match "Details.*.*pwsh.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_powershell_as_service";
    $detectedMessage = "Detects that a powershell code is written to the registry as a service.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*.*\Services\.*" -and $_.message -match "TargetObject.*.*\ImagePath" -and ($_.message -match "Details.*.*powershell.*" -or $_.message -match "Details.*.*pwsh.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}
