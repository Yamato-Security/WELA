# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.ID -eq "1") -and ($_.message -match "Description.*PAExec Application" -or $_.message -match "OriginalFileName.*PAExec.exe")) -and  -not (($_.message -match "Image.*.*\\PAexec.exe" -or $_.message -match "Image.*.*\\paexec.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_renamed_paexec";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_renamed_paexec";
            $detectedMessage = "Detects suspicious renamed PAExec execution as often used by attackers";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.ID -eq "1") -and ($_.message -match "Description.*PAExec Application" -or $_.message -match "OriginalFileName.*PAExec.exe")) -and -not (($_.message -match "Image.*.*\\PAexec.exe" -or $_.message -match "Image.*.*\\paexec.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
