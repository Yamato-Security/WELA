# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*localgroup.*" -and $_.message -match "CommandLine.*.*admin.*" -and $_.message -match "CommandLine.*.*/add.*") -or ($_.message -match "CommandLine.*.*\Win64.exe.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_hurricane_panda";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_apt_hurricane_panda";
            $detectedMessage = "Detects Hurricane Panda Activity";
            $result = $event | where { (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*localgroup.*" -and $_.message -match "CommandLine.*.*admin.*" -and $_.message -match "CommandLine.*.*/add.*") -or ($_.message -match "CommandLine.*.*\\Win64.exe.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
