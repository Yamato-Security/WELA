# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ParentCommandLine.*.*cmd.*" -and $_.message -match "ParentCommandLine.*.*/c.*" -and $_.message -match "CommandLine.*.*/../../.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_commandline_path_traversal";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_commandline_path_traversal";
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "ParentCommandLine.*.*cmd.*" -and $_.message -match "ParentCommandLine.*.*/c.*" -and $_.message -match "CommandLine.*.*/../../.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
