# Get-WinEvent -LogName Security | where {(($_.message -match "LogonType.*3" -and $_.message -match "LogonProcessName.*NtLmSsp" -and $_.message -match "WorkstationName.*%Workstations%" -and $_.message -match "ComputerName.*%Workstations%" -and ($_.ID -eq "4624" -or $_.ID -eq "4625")) -and  -not ($_.message -match "AccountName.*ANONYMOUS LOGON")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_pass_the_hash";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_pass_the_hash";
            $detectedMessage = "Detects the attack technique pass the hash which is used to move laterally inside the network";
            $result = $event |  where { (($_.message -match "LogonType.*3" -and $_.message -match "LogonProcessName.*NtLmSsp" -and $_.message -match "WorkstationName.*%Workstations%" -and $_.message -match "ComputerName.*%Workstations%" -and ($_.ID -eq "4624" -or $_.ID -eq "4625")) -and -not ($_.message -match "AccountName.*ANONYMOUS LOGON")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error" -Foreground Yellow;
    }
}
