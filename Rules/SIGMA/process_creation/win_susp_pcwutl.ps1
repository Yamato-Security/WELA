# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\rundll32.exe" -and $_.message -match "CommandLine.*.*pcwutl.*" -and $_.message -match "CommandLine.*.*LaunchApplication.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_pcwutl";
    $detectedMessage = "Detects launch of executable by calling the LaunchApplication function from pcwutl.dll library."

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "Image.*.*\rundll32.exe" -and $_.message -match "CommandLine.*.*pcwutl.*" -and $_.message -match "CommandLine.*.*LaunchApplication.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}