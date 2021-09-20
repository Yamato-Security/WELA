# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and ($_.message -match "TargetFilename.*.*C:\Windows\System32\spool\drivers\x64\3\old\1\123.*" -or $_.message -match "TargetFilename.*.*C:\Windows\System32\spool\drivers\x64\3\New\.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_cve_2021_1675_printspooler";
    $detectedMessage = "Detects the default filename used in PoC code against print spooler vulnerability CVE-2021-1675";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "11" -and ($_.message -match "TargetFilename.*.*C:\\Windows\\System32\\spool\\drivers\\x64\\3\\old\\1\\123.*" -or $_.message -match "TargetFilename.*.*C:\\Windows\\System32\\spool\\drivers\\x64\\3\\New\\.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
