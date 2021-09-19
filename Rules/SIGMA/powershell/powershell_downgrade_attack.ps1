# Get-WinEvent -LogName Windows PowerShell | where {(($_.ID -eq "400" -and $_.message -match "EngineVersion.*2..*") -and  -not ($_.message -match "HostVersion.*2..*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_downgrade_attack";
    $detectedMessage = "Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "400" -and $_.message -match "EngineVersion.*2..*") -and -not ($_.message -match "HostVersion.*2..*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
