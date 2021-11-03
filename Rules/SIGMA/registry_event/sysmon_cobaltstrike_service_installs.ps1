# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "EventType.*SetValue" -and $_.message -match "TargetObject.*.*HKLM\\System\\CurrentControlSet\\Services" -and (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and (($_.message -match "Details.*.*ADMIN$" -and $_.message -match "Details.*.*.exe") -or ($_.message -match "Details.*.*%COMSPEC%" -and $_.message -match "Details.*.*start" -and $_.message -match "Details.*.*powershell"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_cobaltstrike_service_installs";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_cobaltstrike_service_installs";
            $detectedMessage = "Detects known malicious service installs that appear in cases in which a Cobalt Strike beacon elevates privileges or lateral movement. ";
            $result = $event |  where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "EventType.*SetValue" -and $_.message -match "TargetObject.*.*HKLM\\System\\CurrentControlSet\\Services" -and (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and (($_.message -match "Details.*.*ADMIN$" -and $_.message -match "Details.*.*.exe") -or ($_.message -match "Details.*.*%COMSPEC%" -and $_.message -match "Details.*.*start" -and $_.message -match "Details.*.*powershell"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
