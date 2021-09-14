# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ((($_.ID -eq "1") -and $_.message -match "CommandLine.*.*.cpl" -and  -not (($_.message -match "CommandLine.*.*\System32\.*" -or $_.message -match "CommandLine.*.*%System%.*"))) -or ($_.ID -eq "1" -and $_.message -match "Image.*.*\reg.exe" -and $_.message -match "CommandLine.*.*add.*" -and ($_.message -match "CommandLine.*.*CurrentVersion\Control Panel\CPLs.*")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_control_panel_item";
    $detectedMessage = "Detects the malicious use of a control panel item";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and ((($_.ID -eq "1") -and $_.message -match "CommandLine.*.*.cpl" -and -not (($_.message -match "CommandLine.*.*\System32\.*" -or $_.message -match "CommandLine.*.*%System%.*"))) -or ($_.ID -eq "1" -and $_.message -match "Image.*.*\reg.exe" -and $_.message -match "CommandLine.*.*add.*" -and ($_.message -match "CommandLine.*.*CurrentVersion\Control Panel\CPLs.*")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
