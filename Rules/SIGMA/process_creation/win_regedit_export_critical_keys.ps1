# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\regedit.exe" -and $_.message -match "CommandLine.*.* /E .*" -and ($_.message -match "CommandLine.*.*hklm.*" -or $_.message -match "CommandLine.*.*hkey_local_machine.*") -and ($_.message -match "CommandLine.*.*\system" -or $_.message -match "CommandLine.*.*\sam" -or $_.message -match "CommandLine.*.*\security")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_regedit_export_critical_keys";
    $detectedMessage = "Detects the export of a crital Registry key to a file.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\regedit.exe" -and $_.message -match "CommandLine.*.* /E .*" -and ($_.message -match "CommandLine.*.*hklm.*" -or $_.message -match "CommandLine.*.*hkey_local_machine.*") -and ($_.message -match "CommandLine.*.*\system" -or $_.message -match "CommandLine.*.*\sam" -or $_.message -match "CommandLine.*.*\security")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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