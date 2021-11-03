# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*\SyncAppvPublishingServer.vbs" -and $_.message -match "CommandLine.*"n;" -and $_.message -match "CommandLine.*.*Start-Process ") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "process_creation_syncappvpublishingserver_vbs_execute_powershell";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "process_creation_syncappvpublishingserver_vbs_execute_powershell";
            $detectedMessage = "Adversaries may use scripts signed with trusted certificates to proxy execution of malicious files.";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*\\SyncAppvPublishingServer.vbs" -and $_.message -match "CommandLine.*.*n;" -and $_.message -match "CommandLine.*.*Start-Process ") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
