# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "23" -and ($_.message -match "TargetFilename.*.*.AAA" -or $_.message -match "TargetFilename.*.*.ZZZ")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_sysinternals_sdelete_file_deletion";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_sysinternals_sdelete_file_deletion";
            $detectedMessage = "A General detection to trigger for the deletion of files by Sysinternals SDelete. It looks for the common name pattern used to rename files.";
            $result = $event |  where { ($_.ID -eq "23" -and ($_.message -match "TargetFilename.*.*.AAA" -or $_.message -match "TargetFilename.*.*.ZZZ")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
