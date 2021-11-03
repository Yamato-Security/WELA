# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*findstr") -and ($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*/V" -and $_.message -match "CommandLine.*.*/L") -or ($_.message -match "CommandLine.*.*/S" -and $_.message -match "CommandLine.*.*/I"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_findstr";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_findstr";
            $detectedMessage = "Attackers can use findstr to hide their artifacts or search specific strings and evade defense mechanism";
            $result = $event | where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*findstr") -and ($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*/V" -and $_.message -match "CommandLine.*.*/L") -or ($_.message -match "CommandLine.*.*/S" -and $_.message -match "CommandLine.*.*/I"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
