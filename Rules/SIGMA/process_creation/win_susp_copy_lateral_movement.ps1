# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.ID -eq "1") -and ((($_.message -match "Image.*.*\robocopy.exe" -or $_.message -match "Image.*.*\xcopy.exe") -or ($_.message -match "Image.*.*\cmd.exe" -and $_.message -match "CommandLine.*.*copy.*")) -or ($_.message -match "Image.*.*\powershell.*" -and ($_.message -match "CommandLine.*.*copy-item.*" -or $_.message -match "CommandLine.*.*copy.*" -or $_.message -match "CommandLine.*.*cpi .*" -or $_.message -match "CommandLine.*.* cp .*"))) -and ($_.message -match "CommandLine.*.*\\.*" -and $_.message -match "CommandLine.*.*$.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_copy_lateral_movement";
    $detectedMessage = "Detects a suspicious copy command to or from an Admin share";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and ($_.ID -eq "1") -and ((($_.message -match "Image.*.*\robocopy.exe" -or $_.message -match "Image.*.*\xcopy.exe") -or ($_.message -match "Image.*.*\cmd.exe" -and $_.message -match "CommandLine.*.*copy.*")) -or ($_.message -match "Image.*.*\powershell.*" -and ($_.message -match "CommandLine.*.*copy-item.*" -or $_.message -match "CommandLine.*.*copy.*" -or $_.message -match "CommandLine.*.*cpi .*" -or $_.message -match "CommandLine.*.* cp .*"))) -and ($_.message -match "CommandLine.*.*\\.*" -and $_.message -match "CommandLine.*.*$.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
