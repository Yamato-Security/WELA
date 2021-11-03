# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.ID -eq "1" -and ($_.message -match "Product.*.*PAExec") -and ($_.message -match "11D40A7B7876288F919AB819CC2D9802" -or $_.message -match "6444f8a34e99b8f7d9647de66aabe516" -or $_.message -match "dfd6aa3f7b2b1035b76b718f1ddc689f" -or $_.message -match "1a6cca4d5460b1710a12dea39e4a592c")) -and  -not ($_.message -match "Image.*.*paexec")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_renamed_paexec";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_renamed_paexec";
            $detectedMessage = "Detects execution of renamed paexec via imphash and executable product string";
            $result = $event |  where { (($_.ID -eq "1") -and ($_.ID -eq "1" -and ($_.message -match "Product.*.*PAExec") -and ($_.message -match "11D40A7B7876288F919AB819CC2D9802" -or $_.message -match "6444f8a34e99b8f7d9647de66aabe516" -or $_.message -match "dfd6aa3f7b2b1035b76b718f1ddc689f" -or $_.message -match "1a6cca4d5460b1710a12dea39e4a592c")) -and -not ($_.message -match "Image.*.*paexec")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
