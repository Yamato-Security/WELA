# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "Product.*.*Mouse Lock.*" -or $_.message -match "Company.*.*Misc314.*" -or $_.message -match "CommandLine.*.*Mouse Lock_.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_mouse_lock";
    $detectedMessage = "In Kaspersky's 2020 Incident Response Analyst Report they listed legitimate tool ""Mouse Lock"" as being used for both credential access and collection in security incidents.";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "Product.*.*Mouse Lock.*" -or $_.message -match "Company.*.*Misc314.*" -or $_.message -match "CommandLine.*.*Mouse Lock_.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
