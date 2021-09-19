# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\powershell.exe" -and ($_.message -match "CommandLine.*.*-DisableBehaviorMonitoring $true.*" -or $_.message -match "CommandLine.*.*-DisableRuntimeMonitoring $true.*")) -or ($_.message -match "CommandLine.*.*sc.*" -and $_.message -match "CommandLine.*.*stop.*" -and $_.message -match "CommandLine.*.*WinDefend.*") -or ($_.message -match "CommandLine.*.*sc.*" -and $_.message -match "CommandLine.*.*config.*" -and $_.message -match "CommandLine.*.*WinDefend.*" -and $_.message -match "CommandLine.*.*start=disabled.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_powershell_disable_windef_av";
    $detectedMessage = "Detects attackers attempting to disable Windows Defender using Powershell";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\powershell.exe" -and ($_.message -match "CommandLine.*.*-DisableBehaviorMonitoring $true.*" -or $_.message -match "CommandLine.*.*-DisableRuntimeMonitoring $true.*")) -or ($_.message -match "CommandLine.*.*sc.*" -and $_.message -match "CommandLine.*.*stop.*" -and $_.message -match "CommandLine.*.*WinDefend.*") -or ($_.message -match "CommandLine.*.*sc.*" -and $_.message -match "CommandLine.*.*config.*" -and $_.message -match "CommandLine.*.*WinDefend.*" -and $_.message -match "CommandLine.*.*start=disabled.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
