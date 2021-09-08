# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*findstr.*") -and ($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*/V.*" -and $_.message -match "CommandLine.*.*/L.*") -or ($_.message -match "CommandLine.*.*/S.*" -and $_.message -match "CommandLine.*.*/I.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_findstr";
    $detectedMessage = "Attackers can use findstr to hide their artifacts or search specific strings and evade defense mechanism"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*findstr.*") -and ($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*/V.*" -and $_.message -match "CommandLine.*.*/L.*") -or ($_.message -match "CommandLine.*.*/S.*" -and $_.message -match "CommandLine.*.*/I.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
