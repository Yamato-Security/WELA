# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.ID -eq "1" -and ($_.message -match "Product.*.*PAExec.*") -and ($_.message -match "11D40A7B7876288F919AB819CC2D9802" -or $_.message -match "6444f8a34e99b8f7d9647de66aabe516" -or $_.message -match "dfd6aa3f7b2b1035b76b718f1ddc689f" -or $_.message -match "1a6cca4d5460b1710a12dea39e4a592c")) -and  -not ($_.message -match "Image.*.*paexec.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_renamed_paexec";
    $detectedMessage = "Detects execution of renamed paexec via imphash and executable product string"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and ($_.ID -eq "1" -and ($_.message -match "Product.*.*PAExec.*") -and ($_.message -match "11D40A7B7876288F919AB819CC2D9802" -or $_.message -match "6444f8a34e99b8f7d9647de66aabe516" -or $_.message -match "dfd6aa3f7b2b1035b76b718f1ddc689f" -or $_.message -match "1a6cca4d5460b1710a12dea39e4a592c")) -and -not ($_.message -match "Image.*.*paexec.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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