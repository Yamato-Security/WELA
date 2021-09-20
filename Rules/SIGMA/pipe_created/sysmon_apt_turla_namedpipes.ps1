# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "17" -or $_.ID -eq "18") -and ($_.message -match "\atctl" -or $_.message -match "\userpipe" -or $_.message -match "\iehelper" -or $_.message -match "\sdlrpc" -or $_.message -match "\comnap")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_apt_turla_namedpipes";
    $detectedMessage = "Detects a named pipe used by Turla group samples";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "17" -or $_.ID -eq "18") -and ($_.message -match "\\atctl" -or $_.message -match "\\userpipe" -or $_.message -match "\\iehelper" -or $_.message -match "\\sdlrpc" -or $_.message -match "\\comnap")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
