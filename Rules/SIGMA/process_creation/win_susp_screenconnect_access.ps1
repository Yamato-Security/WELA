# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*e=Access&.*" -and $_.message -match "CommandLine.*.*y=Guest&.*" -and $_.message -match "CommandLine.*.*&p=.*" -and $_.message -match "CommandLine.*.*&c=.*" -and $_.message -match "CommandLine.*.*&k=.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_screenconnect_access";
    $detectedMessage = "Detects ScreenConnect program starts that establish a remote access to that system (not meeting, not remote support)";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*e=Access&.*" -and $_.message -match "CommandLine.*.*y=Guest&.*" -and $_.message -match "CommandLine.*.*&p=.*" -and $_.message -match "CommandLine.*.*&c=.*" -and $_.message -match "CommandLine.*.*&k=.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
