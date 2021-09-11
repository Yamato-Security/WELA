# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "7") -and (($_.message -match "ImageLoaded.*.*\credui.dll" -or $_.message -match "ImageLoaded.*.*\wincredui.dll") -or ($_.message -match "credui.dll" -or $_.message -match "wincredui.dll"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_uipromptforcreds_dlls";
    $detectedMessage = "Detects potential use of UIPromptForCredentials functions by looking for some of the DLLs needed for it.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "7") -and (($_.message -match "ImageLoaded.*.*\credui.dll" -or $_.message -match "ImageLoaded.*.*\wincredui.dll") -or ($_.message -match "credui.dll" -or $_.message -match "wincredui.dll"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
