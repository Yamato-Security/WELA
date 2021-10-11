# Get-WinEvent -LogName Microsoft-Windows-NTLM/Operational | where {($_.ID -eq "8002" -and $_.message -match "CallingProcessName.*.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_ntlm_auth";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_ntlm_auth";
            $detectedMessage = "Detects logons using NTLM, which could be caused by a legacy source or attackers";
            $result = $event |  where { ($_.ID -eq "8002" -and $_.message -match "CallingProcessName.*.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
