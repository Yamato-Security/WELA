# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "ParentImage.*.*\\userinit.exe" -and  -not ($_.message -match "CommandLine.*.*\\netlogon\\.*")) -and  -not ($_.message -match "Image.*.*\\explorer.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_userinit_child";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_userinit_child";
            $detectedMessage = "Detects a suspicious child process of userinit";
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "ParentImage.*.*\\userinit.exe" -and -not ($_.message -match "CommandLine.*.*\\netlogon\\.*")) -and -not ($_.message -match "Image.*.*\\explorer.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
