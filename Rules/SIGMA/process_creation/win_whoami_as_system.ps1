# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "User.*NT AUTHORITY\\SYSTEM" -and $_.message -match "Image.*.*\\whoami.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_whoami_as_system";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_whoami_as_system";
            $detectedMessage = "Detects a whoami.exe executed by LOCAL SYSTEM. This may be a sign of a successful local privilege escalation.";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "User.*NT AUTHORITY\\SYSTEM" -and $_.message -match "Image.*.*\\whoami.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
