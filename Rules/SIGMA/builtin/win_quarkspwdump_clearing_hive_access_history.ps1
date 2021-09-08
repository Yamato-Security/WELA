# Get-WinEvent -LogName System | where {($_.ID -eq "16" -and $_.message -match "HiveName.*.*\AppData\Local\Temp\SAM.*" -and $_.message -match "HiveName.*.*.dmp") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_quarkspwdump_clearing_hive_access_history";
    $detectedMessage = "Detects QuarksPwDump clearing access history in hive";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "16" -and $_.message -match "HiveName.*.*\AppData\Local\Temp\SAM.*" -and $_.message -match "HiveName.*.*.dmp") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
