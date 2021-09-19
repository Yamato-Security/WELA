# Get-WinEvent -LogName Microsoft-Windows-NTLM/Operational | where {($_.ID -eq "8002" -and $_.message -match "CallingProcessName.*.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_ntlm_auth";
    $detectedMessage = "Detects logons using NTLM, which could be caused by a legacy source or attackers";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "8002" -and $_.message -match "CallingProcessName.*.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}
