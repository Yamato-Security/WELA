# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\reg.exe" -and ($_.message -match "CommandLine.*.*query.*" -or $_.message -match "CommandLine.*.*save.*" -or $_.message -match "CommandLine.*.*export.*") -and ($_.message -match "CommandLine.*.*currentVersion\\windows.*" -or $_.message -match "CommandLine.*.*currentVersion\\runServicesOnce.*" -or $_.message -match "CommandLine.*.*currentVersion\\runServices.*" -or $_.message -match "CommandLine.*.*winlogon\\.*" -or $_.message -match "CommandLine.*.*currentVersion\\shellServiceObjectDelayLoad.*" -or $_.message -match "CommandLine.*.*currentVersion\\runOnce.*" -or $_.message -match "CommandLine.*.*currentVersion\\runOnceEx.*" -or $_.message -match "CommandLine.*.*currentVersion\\run.*" -or $_.message -match "CommandLine.*.*currentVersion\\policies\\explorer\\run.*" -or $_.message -match "CommandLine.*.*currentcontrolset\\services.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_query_registry";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "win_query_registry";
                    $detectedMessage = "Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.";
                $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\reg.exe" -and ($_.message -match "CommandLine.*.*query.*" -or $_.message -match "CommandLine.*.*save.*" -or $_.message -match "CommandLine.*.*export.*") -and ($_.message -match "CommandLine.*.*currentVersion\\windows.*" -or $_.message -match "CommandLine.*.*currentVersion\\runServicesOnce.*" -or $_.message -match "CommandLine.*.*currentVersion\\runServices.*" -or $_.message -match "CommandLine.*.*winlogon\\.*" -or $_.message -match "CommandLine.*.*currentVersion\\shellServiceObjectDelayLoad.*" -or $_.message -match "CommandLine.*.*currentVersion\\runOnce.*" -or $_.message -match "CommandLine.*.*currentVersion\\runOnceEx.*" -or $_.message -match "CommandLine.*.*currentVersion\\run.*" -or $_.message -match "CommandLine.*.*currentVersion\\policies\\explorer\\run.*" -or $_.message -match "CommandLine.*.*currentcontrolset\\services.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
