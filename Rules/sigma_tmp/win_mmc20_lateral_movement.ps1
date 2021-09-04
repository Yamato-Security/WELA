# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\svchost.exe" -and $_.message -match "Image.*.*\mmc.exe" -and $_.message -match "CommandLine.*.*-Embedding.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_mmc20_lateral_movement";
    $detectedMessage = "Detects MMC20.Application Lateral Movement; specifically looks for the spawning of the parent MMC.exe with a command line of "-Embedding" as a child of svchost.exe"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\svchost.exe" -and $_.message -match "Image.*.*\mmc.exe" -and $_.message -match "CommandLine.*.*-Embedding.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
