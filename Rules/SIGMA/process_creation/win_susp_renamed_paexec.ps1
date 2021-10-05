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
