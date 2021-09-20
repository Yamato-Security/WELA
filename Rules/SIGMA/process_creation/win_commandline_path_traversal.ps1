# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ParentCommandLine.*.*cmd.*" -and $_.message -match "ParentCommandLine.*.*/c.*" -and $_.message -match "CommandLine.*.*/../../.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_commandline_path_traversal";
    $detectedMessage = "detects the usage of path traversal in cmd.exe indicating possible command/argument confusion/hijacking";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "ParentCommandLine.*.*cmd.*" -and $_.message -match "ParentCommandLine.*.*/c.*" -and $_.message -match "CommandLine.*.*/../../.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
