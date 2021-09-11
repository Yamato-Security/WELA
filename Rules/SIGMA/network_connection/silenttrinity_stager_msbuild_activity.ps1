# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "3" -and $_.message -match "ParentImage.*.*\msbuild.exe" -and ($_.message -match "80" -or $_.message -match "443") -and $_.message -match "Initiated.*true") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "silenttrinity_stager_msbuild_activity";
    $detectedMessage = "Detects a possible remote connections to Silenttrinity c2";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "3" -and $_.message -match "ParentImage.*.*\msbuild.exe" -and ($_.message -match "80" -or $_.message -match "443") -and $_.message -match "Initiated.*true") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
