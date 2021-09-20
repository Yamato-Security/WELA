# Get-WinEvent -LogName Windows PowerShell | where {(($_.ID -eq "400" -and $_.message -match "HostName.*ConsoleHost") -and  -not (($_.message -match "HostApplication.*powershell.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_renamed_powershell";
    $detectedMessage = "Detects renamed powershell";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "400" -and $_.message -match "HostName.*ConsoleHost") -and -not (($_.message -match "HostApplication.*powershell.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
