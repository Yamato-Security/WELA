# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "23" -and ($_.message -match "TargetFilename.*.*.AAA" -or $_.message -match "TargetFilename.*.*.ZZZ")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_sysinternals_sdelete_file_deletion";
    $detectedMessage = "A General detection to trigger for the deletion of files by Sysinternals SDelete. It looks for the common name pattern used to rename files."

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "23" -and ($_.message -match "TargetFilename.*.*.AAA" -or $_.message -match "TargetFilename.*.*.ZZZ")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
