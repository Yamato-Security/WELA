# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\SyncAppvPublishingServer.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where { ($_.message -match ".*SyncAppvPublishingServer.exe.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "win_syncappvpublishingserver_exe";
    $detectedMessage = "Detects SyncAppvPublishingServer process execution which usually utilized by adversaries to bypass PowerShell execution restrictions.";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $results = @();
            $results += $event | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\SyncAppvPublishingServer.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.message -match ".*SyncAppvPublishingServer.exe.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            
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
