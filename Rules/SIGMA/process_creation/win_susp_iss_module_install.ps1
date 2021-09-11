# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\appcmd.exe" -and $_.message -match "CommandLine.*.*install.*" -and $_.message -match "CommandLine.*.*module.*" -and $_.message -match "CommandLine.*.*/name:.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_iss_module_install";
    $detectedMessage = "Detects suspicious IIS native-code module installations via command line";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\appcmd.exe" -and $_.message -match "CommandLine.*.*install.*" -and $_.message -match "CommandLine.*.*module.*" -and $_.message -match "CommandLine.*.*/name:.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
