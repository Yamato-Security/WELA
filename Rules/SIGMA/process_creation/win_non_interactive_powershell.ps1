# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and $_.message -match "Image.*.*\powershell.exe" -and  -not (($_.message -match "ParentImage.*.*\explorer.exe" -or $_.message -match "ParentImage.*.*\CompatTelRunner.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_non_interactive_powershell";
    $detectedMessage = "Detects non-interactive PowerShell activity by looking at powershell.exe with not explorer.exe as a parent."

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and $_.message -match "Image.*.*\powershell.exe" -and -not (($_.message -match "ParentImage.*.*\explorer.exe" -or $_.message -match "ParentImage.*.*\CompatTelRunner.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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