# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "23" -and ($_.message -match "Image.*.*spoolsv.exe") -and ($_.message -match "TargetFilename.*.*C:\Windows\System32\spool\drivers\x64\3\.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_cve_2021_1675_printspooler_del";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_cve_2021_1675_printspooler_del";
            $detectedMessage = "Detect DLL deletions from Spooler Service driver folder ";
            $result = $event |  where { ($_.ID -eq "23" -and ($_.message -match "Image.*.*spoolsv.exe") -and ($_.message -match "TargetFilename.*.*C:\\Windows\\System32\\spool\\drivers\\x64\\3\\.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
