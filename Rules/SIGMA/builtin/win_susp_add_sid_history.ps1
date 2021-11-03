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
            $result = $event |  where { ((($_.ID -eq "4765" -or $_.ID -eq "4766") -or (($_.ID -eq "4738" -and -not (($_.message -match "-" -or $_.message -match "%%1793"))) -and -not (-not $_.message -match "SidHistory")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
