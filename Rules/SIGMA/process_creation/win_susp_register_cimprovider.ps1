# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\register-cimprovider.exe" -and $_.message -match "CommandLine.*.*-path.*" -and $_.message -match "CommandLine.*.*dll.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_register_cimprovider";
    $detectedMessage = "Detects using register-cimprovider.exe to execute arbitrary dll file.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\register-cimprovider.exe" -and $_.message -match "CommandLine.*.*-path.*" -and $_.message -match "CommandLine.*.*dll.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
