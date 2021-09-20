# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\advanced_ip_scanner.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*\\AppData\\Local\\Temp\\Advanced IP Scanner 2.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_advanced_ip_scanner";
    $detectedMessage = "Detects the use of Advanced IP Scanner. Seems to be a popular tool for ransomware groups.";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            $results = @();
            $results += $event | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\advanced_ip_scanner.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*\\AppData\\Local\\Temp\\Advanced IP Scanner 2.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            
            foreach ($result in $results) {
                if ($result.Count -ne 0) {
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $result
                    Write-Host $detectedMessage;    
                }
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
