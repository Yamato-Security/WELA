# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\sc.exe" -and $_.message -match "CommandLine.*.*create" -and $_.message -match "CommandLine.*.*binpath") -or ($_.message -match "Image.*.*\powershell.exe" -and $_.message -match "CommandLine.*.*new-service"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_new_service_creation";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_new_service_creation";
            $detectedMessage = "Detects creation of a new service.";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "Image.*.*\\sc.exe" -and $_.message -match "CommandLine.*.*create" -and $_.message -match "CommandLine.*.*binpath") -or ($_.message -match "Image.*.*\\powershell.exe" -and $_.message -match "CommandLine.*.*new-service"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
