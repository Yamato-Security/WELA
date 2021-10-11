# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\SyncAppvPublishingServer.exe" -and $_.message -match "CommandLine.*.*"n; .*" -and $_.message -match "CommandLine.*.* Start-Process .*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "process_creation_syncappvpublishingserver_execute_arbitrary_powershell";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "process_creation_syncappvpublishingserver_execute_arbitrary_powershell";
            $detectedMessage = "Executes arbitrary PowerShell code using SyncAppvPublishingServer.exe.";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\SyncAppvPublishingServer.exe" -and $_.message -match "CommandLine.*.*n; .*" -and $_.message -match "CommandLine.*.* Start-Process .*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error" -Foreground Yellow;
    }
}
