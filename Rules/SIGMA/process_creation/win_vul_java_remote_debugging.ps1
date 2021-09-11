# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and $_.message -match "CommandLine.*.*transport=dt_socket,address=.*" -and  -not ($_.message -match "CommandLine.*.*address=127.0.0.1.*" -or $_.message -match "CommandLine.*.*address=localhost.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_vul_java_remote_debugging";
    $detectedMessage = "Detects a JAVA process running with remote debugging allowing more than just localhost to connect";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and $_.message -match "CommandLine.*.*transport=dt_socket,address=.*" -and -not ($_.message -match "CommandLine.*.*address=127.0.0.1.*" -or $_.message -match "CommandLine.*.*address=localhost.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
