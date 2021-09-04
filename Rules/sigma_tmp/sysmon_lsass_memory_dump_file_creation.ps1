# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*lsass.*" -and $_.message -match "TargetFilename.*.*dmp") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_lsass_memory_dump_file_creation";
    $detectedMessage = "LSASS memory dump creation using operating systems utilities. Procdump will use process name in output file if no name is specified"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*lsass.*" -and $_.message -match "TargetFilename.*.*dmp") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
