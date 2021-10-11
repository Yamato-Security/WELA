# Get-WinEvent | where {(($_.message -match "Microsoft-Windows-AppLocker/MSI and Script" -or $_.message -match "Microsoft-Windows-AppLocker/EXE and DLL" -or $_.message -match "Microsoft-Windows-AppLocker/Packaged app-Deployment" -or $_.message -match "Microsoft-Windows-AppLocker/Packaged app-Execution") -and ($_.ID -eq "8004" -or $_.ID -eq "8007")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_applocker_file_was_not_allowed_to_run";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_applocker_file_was_not_allowed_to_run";
            $detectedMessage = "Detect run not allowed files. Applocker is a very useful tool, especially on servers where unprivileged users have access. For example terminal servers. You need configure applocker and log collect to receive these events.";
            $result = $event | where { (($_.message -match "Microsoft-Windows-AppLocker/MSI and Script" -or $_.message -match "Microsoft-Windows-AppLocker/EXE and DLL" -or $_.message -match "Microsoft-Windows-AppLocker/Packaged app-Deployment" -or $_.message -match "Microsoft-Windows-AppLocker/Packaged app-Execution") -and ($_.ID -eq "8004" -or $_.ID -eq "8007")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error" -Foreground Yellow;
    }
}
