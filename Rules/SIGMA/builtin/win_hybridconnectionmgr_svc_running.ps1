# Get-WinEvent | where {(($_.ID -eq "40300" -or $_.ID -eq "40301" -or $_.ID -eq "40302") -and ($_.message -match ".*HybridConnection.*" -or $_.message -match ".*sb://.*" -or $_.message -match ".*servicebus.windows.net.*" -or $_.message -match ".*HybridConnectionManage.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_hybridconnectionmgr_svc_running";
    $detectedMessage = "Rule to detect the Hybrid Connection Manager service running on an endpoint.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { (($_.ID -eq "40300" -or $_.ID -eq "40301" -or $_.ID -eq "40302") -and ($_.message -match ".*HybridConnection.*" -or $_.message -match ".*sb://.*" -or $_.message -match ".*servicebus.windows.net.*" -or $_.message -match ".*HybridConnectionManage.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
