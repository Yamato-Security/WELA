# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "11") -and (($_.message -match "TargetFilename.*.*\hive_sam_" -or $_.message -match "TargetFilename.*.*\SAM-2021-" -or $_.message -match "TargetFilename.*.*\SAM-2022-" -or $_.message -match "TargetFilename.*.*\SAM-haxx" -or $_.message -match "TargetFilename.*.*\Sam.save") -or ($_.message -match "C:\windows\temp\sam"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_hivenightmare_file_exports";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_hivenightmare_file_exports";
            $detectedMessage = "Detects files written by the different tools that exploit HiveNightmare";
            $result = $event |  where { (($_.ID -eq "11") -and (($_.message -match "TargetFilename.*.*\\hive_sam_" -or $_.message -match "TargetFilename.*.*\\SAM-2021-" -or $_.message -match "TargetFilename.*.*\\SAM-2022-" -or $_.message -match "TargetFilename.*.*\\SAM-haxx" -or $_.message -match "TargetFilename.*.*\\Sam.save") -or ($_.message -match "C:\\windows\\temp\\sam"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
