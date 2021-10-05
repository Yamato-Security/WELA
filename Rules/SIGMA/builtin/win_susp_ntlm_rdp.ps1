# Get-WinEvent -LogName Microsoft-Windows-NTLM/Operational | where {($_.ID -eq "8001" -and $_.message -match "TargetName.*TERMSRV.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_ntlm_rdp";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_ntlm_rdp";
            $detectedMessage = "Detects logons using NTLM to hosts that are potentially not part of the domain.";
            $result = $event |  where { ($_.ID -eq "8001" -and $_.message -match "TargetName.*TERMSRV.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    $ruleStack.Add($ruleName, $detectRule);
}
