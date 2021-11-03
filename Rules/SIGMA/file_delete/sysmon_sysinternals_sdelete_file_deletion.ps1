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
