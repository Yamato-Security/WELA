# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "11") -and (($_.message -match "TargetFilename.*.*\hive_sam_.*" -or $_.message -match "TargetFilename.*.*\SAM-2021-.*" -or $_.message -match "TargetFilename.*.*\SAM-2022-.*" -or $_.message -match "TargetFilename.*.*\SAM-haxx.*" -or $_.message -match "TargetFilename.*.*\Sam.save.*") -or ($_.message -match "C:\windows\temp\sam"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_hivenightmare_file_exports";
    $detectedMessage = "Detects files written by the different tools that exploit HiveNightmare"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "11") -and (($_.message -match "TargetFilename.*.*\hive_sam_.*" -or $_.message -match "TargetFilename.*.*\SAM-2021-.*" -or $_.message -match "TargetFilename.*.*\SAM-2022-.*" -or $_.message -match "TargetFilename.*.*\SAM-haxx.*" -or $_.message -match "TargetFilename.*.*\Sam.save.*") -or ($_.message -match "C:\windows\temp\sam"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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