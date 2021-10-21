# Get-WinEvent -LogName Security | where {((($_.ID -eq "528" -or $_.ID -eq "529" -or $_.ID -eq "4624" -or $_.ID -eq "4625") -and $_.message -match "LogonType.*2" -and ($_.message -match "%ServerSystems%" -or $_.message -match "%DomainControllers%")) -and  -not ($_.message -match "LogonProcessName.*Advapi" -and $_.message -match "ComputerName.*%Workstations%")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_interactive_logons";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_interactive_logons";
            $detectedMessage = "Detects interactive console logons to Server Systems";
            $result = $event |  where { ((($_.ID -eq "528" -or $_.ID -eq "529" -or $_.ID -eq "4624" -or $_.ID -eq "4625") -and $_.message -match "LogonType.*2" -and ($_.message -match "%ServerSystems%" -or $_.message -match "%DomainControllers%")) -and -not ($_.message -match "LogonProcessName.*Advapi" -and $_.message -match "ComputerName.*%Workstations%")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
