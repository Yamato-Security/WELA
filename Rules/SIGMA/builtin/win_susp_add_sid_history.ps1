# Get-WinEvent -LogName Security | where {((($_.ID -eq "4765" -or $_.ID -eq "4766") -or (($_.ID -eq "4738" -and  -not (($_.message -match "-" -or $_.message -match "%%1793"))) -and  -not (-not SidHistory="*")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_add_sid_history";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_add_sid_history";
            $detectedMessage = "An attacker can use the SID history attribute to gain additional privileges.";
            $result = $event |  where { ((($_.ID -eq "4765" -or $_.ID -eq "4766") -or (($_.ID -eq "4738" -and -not (($_.message -match "-" -or $_.message -match "%%1793"))) -and -not (-not $_.message -match "SidHistory.*")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
