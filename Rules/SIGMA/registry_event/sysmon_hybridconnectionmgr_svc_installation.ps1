# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "TargetObject.*.*\\Services\\HybridConnectionManager.*" -or $_.message -match "Details.*.*Microsoft.HybridConnectionManager.Listener.exe.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_hybridconnectionmgr_svc_installation";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "sysmon_hybridconnectionmgr_svc_installation";
                    $detectedMessage = "Detects the installation of the Azure Hybrid Connection Manager service to allow remote code execution from Azure function.";
                $result = $event |  where { ((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "TargetObject.*.*\\Services\\HybridConnectionManager.*" -or $_.message -match "Details.*.*Microsoft.HybridConnectionManager.Listener.exe.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
