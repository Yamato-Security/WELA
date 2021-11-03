# Get-WinEvent -LogName Windows PowerShell | where {(($_.ID -eq "400" -and $_.message -match "EngineVersion.*2.") -and  -not ($_.message -match "HostVersion.*2.")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_downgrade_attack";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "powershell_downgrade_attack";
            $detectedMessage = "Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0";
            $result = $event |  where { (($_.ID -eq "400" -and $_.message -match "EngineVersion.*2.") -and -not ($_.message -match "HostVersion.*2.")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
