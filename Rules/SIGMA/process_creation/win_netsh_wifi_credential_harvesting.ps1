# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\netsh.exe" -and $_.message -match "CommandLine.*.*wlan.*" -and $_.message -match "CommandLine.*.* s.*" -and $_.message -match "CommandLine.*.* p.*" -and $_.message -match "CommandLine.*.* k.*" -and $_.message -match "CommandLine.*.*=clear.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_netsh_wifi_credential_harvesting";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "win_netsh_wifi_credential_harvesting";
                    $detectedMessage = "Detect the harvesting of wifi credentials using netsh.exe";
                $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\netsh.exe" -and $_.message -match "CommandLine.*.*wlan.*" -and $_.message -match "CommandLine.*.* s.*" -and $_.message -match "CommandLine.*.* p.*" -and $_.message -match "CommandLine.*.* k.*" -and $_.message -match "CommandLine.*.*=clear.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
