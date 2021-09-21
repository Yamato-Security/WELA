# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*findstr.*") -and ($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*/V.*" -and $_.message -match "CommandLine.*.*/L.*") -or ($_.message -match "CommandLine.*.*/S.*" -and $_.message -match "CommandLine.*.*/I.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_findstr";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_findstr";
            $detectedMessage = "Attackers can use findstr to hide their artifacts or search specific strings and evade defense mechanism";
            $result = $event | where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*findstr.*") -and ($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*/V.*" -and $_.message -match "CommandLine.*.*/L.*") -or ($_.message -match "CommandLine.*.*/S.*" -and $_.message -match "CommandLine.*.*/I.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
