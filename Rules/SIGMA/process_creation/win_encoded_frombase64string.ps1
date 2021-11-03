# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*OjpGcm9tQmFzZTY0U3RyaW5n" -or $_.message -match "CommandLine.*.*o6RnJvbUJhc2U2NFN0cmluZ" -or $_.message -match "CommandLine.*.*6OkZyb21CYXNlNjRTdHJpbm")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_encoded_frombase64string";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_encoded_frombase64string";
            $detectedMessage = "Detects a base64 encoded FromBase64String keyword in a process command line";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*OjpGcm9tQmFzZTY0U3RyaW5n" -or $_.message -match "CommandLine.*.*o6RnJvbUJhc2U2NFN0cmluZ" -or $_.message -match "CommandLine.*.*6OkZyb21CYXNlNjRTdHJpbm")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result -and $result.Count -ne 0) {
                Write-Output ""; 
                Write-Output "Detected! RuleName:$ruleName";
                Write-Output $detectedMessage;
                Write-Output $result;
                Write-Output ""; 
            }
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
