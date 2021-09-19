# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*\SyncAppvPublishingServer.vbs.*" -and $_.message -match "CommandLine.*.*"n;.*" -and $_.message -match "CommandLine.*.*Start-Process .*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "process_creation_syncappvpublishingserver_vbs_execute_powershell";
    $detectedMessage = "Adversaries may use scripts signed with trusted certificates to proxy execution of malicious files.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*\SyncAppvPublishingServer.vbs.*" -and $_.message -match "CommandLine.*.*n;.*" -and $_.message -match "CommandLine.*.*Start-Process .*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}
