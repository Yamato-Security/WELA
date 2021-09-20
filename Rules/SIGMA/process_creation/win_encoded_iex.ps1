# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*SUVYIChb.*" -or $_.message -match "CommandLine.*.*lFWCAoW.*" -or $_.message -match "CommandLine.*.*JRVggKF.*" -or $_.message -match "CommandLine.*.*aWV4IChb.*" -or $_.message -match "CommandLine.*.*lleCAoW.*" -or $_.message -match "CommandLine.*.*pZXggKF.*" -or $_.message -match "CommandLine.*.*aWV4IChOZX.*" -or $_.message -match "CommandLine.*.*lleCAoTmV3.*" -or $_.message -match "CommandLine.*.*pZXggKE5ld.*" -or $_.message -match "CommandLine.*.*SUVYIChOZX.*" -or $_.message -match "CommandLine.*.*lFWCAoTmV3.*" -or $_.message -match "CommandLine.*.*JRVggKE5ld.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_encoded_iex";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "win_encoded_iex";
                    $detectedMessage = "Detects a base64 encoded IEX command string in a process command line";
                $result = $event |  where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*SUVYIChb.*" -or $_.message -match "CommandLine.*.*lFWCAoW.*" -or $_.message -match "CommandLine.*.*JRVggKF.*" -or $_.message -match "CommandLine.*.*aWV4IChb.*" -or $_.message -match "CommandLine.*.*lleCAoW.*" -or $_.message -match "CommandLine.*.*pZXggKF.*" -or $_.message -match "CommandLine.*.*aWV4IChOZX.*" -or $_.message -match "CommandLine.*.*lleCAoTmV3.*" -or $_.message -match "CommandLine.*.*pZXggKE5ld.*" -or $_.message -match "CommandLine.*.*SUVYIChOZX.*" -or $_.message -match "CommandLine.*.*lFWCAoTmV3.*" -or $_.message -match "CommandLine.*.*JRVggKE5ld.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
