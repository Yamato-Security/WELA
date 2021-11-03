# Get-WinEvent -LogName Security | where {($_.ID -eq "5145" -and $_.message -match "ShareName.*\.*\IPC$" -and $_.message -match "RelativeTargetName.*svcctl" -and $_.message -match "Accesses.*.*WriteData") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_svcctl_remote_service";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_svcctl_remote_service";
            $detectedMessage = "Detects remote service activity via remote access to the svcctl named pipe";
            $result = $event |  where { ($_.ID -eq "5145" -and $_.message -match "ShareName.*\\.*\\IPC$" -and $_.message -match "RelativeTargetName.*svcctl" -and $_.message -match "Accesses.*.*WriteData") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
