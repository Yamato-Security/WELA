# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\SyncAppvPublishingServer.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where { ($_.message -match "SyncAppvPublishingServer.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "win_syncappvpublishingserver_exe";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_syncappvpublishingserver_exe";
            $detectedMessage = "Detects SyncAppvPublishingServer process execution which usually utilized by adversaries to bypass PowerShell execution restrictions.";
            $results = [System.Collections.ArrayList] @();
            $tmp = $event | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\SyncAppvPublishingServer.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { ($_.message -match "SyncAppvPublishingServer.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            [void]$results.Add($tmp);
            
            foreach ($result in $results) {
                if ($result -and $result.Count -ne 0) {
                    Write-Output ""; 
                    Write-Output "Detected! RuleName:$ruleName";
                    Write-Output $detectedMessage;    
                    Write-Output $result;
                    Write-Output ""; 
                }
            }
        };
        . Search-DetectableEvents $args;
    };
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
