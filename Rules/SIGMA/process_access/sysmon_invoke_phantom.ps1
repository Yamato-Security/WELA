# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "10" -and $_.message -match "TargetImage.*.*\windows\system32\svchost.exe" -and $_.message -match "GrantedAccess.*0x1f3fff" -and ($_.message -match "CallTrace.*.*unknown.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_invoke_phantom";
    $detectedMessage = "Detects suspect access to svchost process memory such as that used by Invoke-Phantom to kill the winRM windows event logging service.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "10" -and $_.message -match "TargetImage.*.*\windows\system32\svchost.exe" -and $_.message -match "GrantedAccess.*0x1f3fff" -and ($_.message -match "CallTrace.*.*unknown.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
