# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*taskkill .*" -and $_.message -match "CommandLine.*.*RaccineSettings.exe.*") -or ($_.message -match "CommandLine.*.*reg.exe.*" -and $_.message -match "CommandLine.*.*delete.*" -and $_.message -match "CommandLine.*.*Raccine Tray.*") -or ($_.message -match "CommandLine.*.*schtasks.*" -and $_.message -match "CommandLine.*.*/DELETE.*" -and $_.message -match "CommandLine.*.*Raccine Rules Updater.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_disable_raccine";
    $detectedMessage = "Detects commands that indicate a Raccine removal from an end system. Raccine is a free ransomware protection tool. "

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*taskkill .*" -and $_.message -match "CommandLine.*.*RaccineSettings.exe.*") -or ($_.message -match "CommandLine.*.*reg.exe.*" -and $_.message -match "CommandLine.*.*delete.*" -and $_.message -match "CommandLine.*.*Raccine Tray.*") -or ($_.message -match "CommandLine.*.*schtasks.*" -and $_.message -match "CommandLine.*.*/DELETE.*" -and $_.message -match "CommandLine.*.*Raccine Rules Updater.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
