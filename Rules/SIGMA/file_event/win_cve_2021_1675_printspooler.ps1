# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and ($_.message -match "TargetFilename.*.*C:\Windows\System32\spool\drivers\x64\3\old\1\123" -or $_.message -match "TargetFilename.*.*C:\Windows\System32\spool\drivers\x64\3\New\")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_cve_2021_1675_printspooler";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_cve_2021_1675_printspooler";
            $detectedMessage = "Detects the default filename used in PoC code against print spooler vulnerability CVE-2021-1675";
            $result = $event |  where { ($_.ID -eq "11" -and ($_.message -match "TargetFilename.*.*C:\\Windows\\System32\\spool\\drivers\\x64\\3\\old\\1\\123" -or $_.message -match "TargetFilename.*.*C:\\Windows\\System32\\spool\\drivers\\x64\\3\\New\\")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
