# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\sc.exe" -and $_.message -match "CommandLine.*.*config.*" -and $_.message -match "CommandLine.*.*binpath.*" -and ($_.message -match "CommandLine.*.*powershell.*" -or $_.message -match "CommandLine.*.*cmd.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_service_path_modification";
    $detectedMessage = "Detects service path modification to PowerShell or cmd."

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "Image.*.*\sc.exe" -and $_.message -match "CommandLine.*.*config.*" -and $_.message -match "CommandLine.*.*binpath.*" -and ($_.message -match "CommandLine.*.*powershell.*" -or $_.message -match "CommandLine.*.*cmd.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
