# Get-WinEvent | where {(($_.message -match "Microsoft-Windows-AppLocker/MSI and Script" -or $_.message -match "Microsoft-Windows-AppLocker/EXE and DLL" -or $_.message -match "Microsoft-Windows-AppLocker/Packaged app-Deployment" -or $_.message -match "Microsoft-Windows-AppLocker/Packaged app-Execution") -and ($_.ID -eq "8004" -or $_.ID -eq "8007")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_applocker_file_was_not_allowed_to_run";
    $detectedMessage = "Detect run not allowed files. Applocker is a very useful tool, especially on servers where unprivileged users have access. For example terminal servers. You need configure applocker and log collect to receive these events."

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | !firstpipe!
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