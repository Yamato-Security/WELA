# Get-WinEvent -LogName Security | where {((($_.ID -eq "528" -or $_.ID -eq "529" -or $_.ID -eq "4624" -or $_.ID -eq "4625") -and $_.message -match "LogonType.*2" -and ($_.message -match "%ServerSystems%" -or $_.message -match "%DomainControllers%")) -and  -not ($_.message -match "LogonProcessName.*Advapi" -and $_.message -match "ComputerName.*%Workstations%")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_interactive_logons";
    $detectedMessage = "Detects interactive console logons to Server Systems";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {((($_.ID -eq "528" -or $_.ID -eq "529" -or $_.ID -eq "4624" -or $_.ID -eq "4625") -and $_.message -match "LogonType.*2" -and ($_.message -match "%ServerSystems%" -or $_.message -match "%DomainControllers%")) -and -not ($_.message -match "LogonProcessName.*Advapi" -and $_.message -match "ComputerName.*%Workstations%")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
