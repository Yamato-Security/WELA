# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "Product.*.*Mouse Lock" -or $_.message -match "Company.*.*Misc314" -or $_.message -match "CommandLine.*.*Mouse Lock_")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_mouse_lock";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_mouse_lock";
            $detectedMessage = "In Kaspersky's 2020 Incident Response Analyst Report they listed legitimate tool ""Mouse Lock"" as being used for both credential access and collection in security incidents.";
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "Product.*.*Mouse Lock" -or $_.message -match "Company.*.*Misc314" -or $_.message -match "CommandLine.*.*Mouse Lock_")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
