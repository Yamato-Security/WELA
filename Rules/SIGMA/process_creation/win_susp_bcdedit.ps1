# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\bcdedit.exe" -and ($_.message -match "CommandLine.*.*delete.*" -or $_.message -match "CommandLine.*.*deletevalue.*" -or $_.message -match "CommandLine.*.*import.*" -or $_.message -match "CommandLine.*.*safeboot.*" -or $_.message -match "CommandLine.*.*network.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_bcdedit";
    $detectedMessage = "Detects, possibly, malicious unauthorized usage of bcdedit.exe";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "Image.*.*\bcdedit.exe" -and ($_.message -match "CommandLine.*.*delete.*" -or $_.message -match "CommandLine.*.*deletevalue.*" -or $_.message -match "CommandLine.*.*import.*" -or $_.message -match "CommandLine.*.*safeboot.*" -or $_.message -match "CommandLine.*.*network.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
