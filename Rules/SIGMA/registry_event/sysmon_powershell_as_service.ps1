# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*.*\\Services\\" -and $_.message -match "TargetObject.*.*\\ImagePath" -and ($_.message -match "Details.*.*powershell" -or $_.message -match "Details.*.*pwsh")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_powershell_as_service";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_powershell_as_service";
            $detectedMessage = "Detects that a powershell code is written to the registry as a service.";
            $result = $event |  where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*.*\\Services\\" -and $_.message -match "TargetObject.*.*\\ImagePath" -and ($_.message -match "Details.*.*powershell" -or $_.message -match "Details.*.*pwsh")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
