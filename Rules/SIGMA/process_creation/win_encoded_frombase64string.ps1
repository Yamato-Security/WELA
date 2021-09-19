# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*OjpGcm9tQmFzZTY0U3RyaW5n.*" -or $_.message -match "CommandLine.*.*o6RnJvbUJhc2U2NFN0cmluZ.*" -or $_.message -match "CommandLine.*.*6OkZyb21CYXNlNjRTdHJpbm.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_encoded_frombase64string";
    $detectedMessage = "Detects a base64 encoded FromBase64String keyword in a process command line";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*OjpGcm9tQmFzZTY0U3RyaW5n.*" -or $_.message -match "CommandLine.*.*o6RnJvbUJhc2U2NFN0cmluZ.*" -or $_.message -match "CommandLine.*.*6OkZyb21CYXNlNjRTdHJpbm.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}
