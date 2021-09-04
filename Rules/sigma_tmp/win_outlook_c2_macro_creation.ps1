# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*\Microsoft\Outlook\VbaProject.OTM") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_outlook_c2_macro_creation";
    $detectedMessage = "Detects the creation of a macro file for Outlook. Goes with win_outlook_c2_registry_key. VbaProject.OTM is explicitly mentioned in T1137. Particularly interesting if both events Registry !detection! File Creation happens at the same time. "

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*\Microsoft\Outlook\VbaProject.OTM") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
