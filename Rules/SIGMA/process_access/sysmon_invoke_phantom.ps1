# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "10" -and $_.message -match "TargetImage.*.*\windows\system32\svchost.exe" -and $_.message -match "GrantedAccess.*0x1f3fff" -and ($_.message -match "CallTrace.*.*unknown.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_invoke_phantom";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_invoke_phantom";
            $detectedMessage = "Detects suspect access to svchost process memory such as that used by Invoke-Phantom to kill the winRM windows event logging service.";
            $result = $event |  where { ($_.ID -eq "10" -and $_.message -match "TargetImage.*.*\\windows\\system32\\svchost.exe" -and $_.message -match "GrantedAccess.*0x1f3fff" -and ($_.message -match "CallTrace.*.*unknown.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
