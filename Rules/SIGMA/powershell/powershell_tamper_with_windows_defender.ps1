# Get-WinEvent | where {($_.ID -eq "600" -and $_.message -match "HostApplication.*.*Set-MpPreference.*" -and ($_.message -match "HostApplication.*.*-DisableRealtimeMonitoring 1.*" -or $_.message -match "HostApplication.*.*-DisableBehaviorMonitoring 1.*" -or $_.message -match "HostApplication.*.*-DisableScriptScanning 1.*" -or $_.message -match "HostApplication.*.*-DisableBlockAtFirstSeen 1.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_tamper_with_windows_defender";
    $detectedMessage = "Attempting to disable scheduled scanning and other parts of windows defender atp.";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "600" -and $_.message -match "HostApplication.*.*Set-MpPreference.*" -and ($_.message -match "HostApplication.*.*-DisableRealtimeMonitoring 1.*" -or $_.message -match "HostApplication.*.*-DisableBehaviorMonitoring 1.*" -or $_.message -match "HostApplication.*.*-DisableScriptScanning 1.*" -or $_.message -match "HostApplication.*.*-DisableBlockAtFirstSeen 1.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
