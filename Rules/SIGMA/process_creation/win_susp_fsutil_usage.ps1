# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.ID -eq "1") -and ($_.message -match "Image.*.*\\fsutil.exe" -or $_.message -match "OriginalFileName.*fsutil.exe") -and ($_.message -match "CommandLine.*.*deletejournal.*" -or $_.message -match "CommandLine.*.*createjournal.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_fsutil_usage";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_fsutil_usage";
            $detectedMessage = "Detects suspicious parameters of fsutil (deleting USN journal, configuring it with small size, etc). Might be used by ransomwares during the attack (seen by NotPetya and others).";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.ID -eq "1") -and ($_.message -match "Image.*.*\\fsutil.exe" -or $_.message -match "OriginalFileName.*fsutil.exe") -and ($_.message -match "CommandLine.*.*deletejournal.*" -or $_.message -match "CommandLine.*.*createjournal.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
