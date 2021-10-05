# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*reg.*" -and $_.message -match "CommandLine.*.* ADD .*" -and $_.message -match "CommandLine.*.*Software\\Microsoft\\Windows\\CurrentVersion\\Run.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_reg_add_run_key";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_reg_add_run_key";
            $detectedMessage = "Detects suspicious command line reg.exe tool adding key to RUN key in Registry";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*reg.*" -and $_.message -match "CommandLine.*.* ADD .*" -and $_.message -match "CommandLine.*.*Software\\Microsoft\\Windows\\CurrentVersion\\Run.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
