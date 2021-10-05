# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "Image.*.*\iodine.exe" -or $_.message -match "Image.*.*\dnscat2.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_dns_exfiltration_tools_execution";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_dns_exfiltration_tools_execution";
            $detectedMessage = "Well-known DNS Exfiltration tools execution";
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "Image.*.*\\iodine.exe" -or $_.message -match "Image.*.*\\dnscat2.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
