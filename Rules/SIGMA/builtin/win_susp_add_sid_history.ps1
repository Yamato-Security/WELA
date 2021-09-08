# Get-WinEvent -LogName Security | where {((($_.ID -eq "4765" -or $_.ID -eq "4766") -or (($_.ID -eq "4738" -and  -not (($_.message -match "-" -or $_.message -match "%%1793"))) -and  -not (-not SidHistory="*")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_add_sid_history";
    $detectedMessage = "An attacker can use the SID history attribute to gain additional privileges.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {((($_.ID -eq "4765" -or $_.ID -eq "4766") -or (($_.ID -eq "4738" -and -not (($_.message -match "-" -or $_.message -match "%%1793"))) -and -not (-not SidHistory="*")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
