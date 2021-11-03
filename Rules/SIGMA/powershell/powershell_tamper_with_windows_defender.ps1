# Get-WinEvent | where {($_.ID -eq "600" -and $_.message -match "HostApplication.*.*Set-MpPreference" -and ($_.message -match "HostApplication.*.*-DisableRealtimeMonitoring 1" -or $_.message -match "HostApplication.*.*-DisableBehaviorMonitoring 1" -or $_.message -match "HostApplication.*.*-DisableScriptScanning 1" -or $_.message -match "HostApplication.*.*-DisableBlockAtFirstSeen 1")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_tamper_with_windows_defender";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "powershell_tamper_with_windows_defender";
            $detectedMessage = "Attempting to disable scheduled scanning and other parts of windows defender atp.";
            $result = $event |  where { ($_.ID -eq "600" -and $_.message -match "HostApplication.*.*Set-MpPreference" -and ($_.message -match "HostApplication.*.*-DisableRealtimeMonitoring 1" -or $_.message -match "HostApplication.*.*-DisableBehaviorMonitoring 1" -or $_.message -match "HostApplication.*.*-DisableScriptScanning 1" -or $_.message -match "HostApplication.*.*-DisableBlockAtFirstSeen 1")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result -and $result.Count -ne 0) {
                Write-Output ""; 
                Write-Output "Detected! RuleName:$ruleName";
                Write-Output $detectedMessage;
                Write-Output $result;
                Write-Output ""; 
            }
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
