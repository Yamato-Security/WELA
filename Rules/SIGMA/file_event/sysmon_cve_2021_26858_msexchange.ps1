# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "11") -and $_.message -match "Image.*.*UMWorkerProcess.exe" -and  -not (($_.message -match "TargetFilename.*.*CacheCleanup.bin" -or $_.message -match "TargetFilename.*.*.txt" -or $_.message -match "TargetFilename.*.*.LOG" -or $_.message -match "TargetFilename.*.*.cfg" -or $_.message -match "TargetFilename.*.*cleanup.bin"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_cve_2021_26858_msexchange";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_cve_2021_26858_msexchange";
            $detectedMessage = "Detects possible successful exploitation for vulnerability described in CVE-2021-26858 by looking for |";
            $result = $event |  where { (($_.ID -eq "11") -and $_.message -match "Image.*.*UMWorkerProcess.exe" -and -not (($_.message -match "TargetFilename.*.*CacheCleanup.bin" -or $_.message -match "TargetFilename.*.*.txt" -or $_.message -match "TargetFilename.*.*.LOG" -or $_.message -match "TargetFilename.*.*.cfg" -or $_.message -match "TargetFilename.*.*cleanup.bin"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
