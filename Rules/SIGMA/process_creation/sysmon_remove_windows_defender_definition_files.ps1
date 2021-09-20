# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "OriginalFileName.*MpCmdRun.exe" -and $_.message -match "CommandLine.*.* -RemoveDefinitions.*" -and $_.message -match "CommandLine.*.* -All.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_remove_windows_defender_definition_files";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "sysmon_remove_windows_defender_definition_files";
                    $detectedMessage = "Adversaries may disable security tools to avoid possible detection of their tools and activities by removing Windows Defender Definition Files";
                $result = $event |  where {($_.ID -eq "1" -and $_.message -match "OriginalFileName.*MpCmdRun.exe" -and $_.message -match "CommandLine.*.* -RemoveDefinitions.*" -and $_.message -match "CommandLine.*.* -All.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
