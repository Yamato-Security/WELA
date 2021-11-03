# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "TargetObject.*.*\\services\\TermService\\Parameters\\ServiceDll" -or $_.message -match "TargetObject.*.*\\Control\\Terminal Server\\fSingleSessionPerUser" -or $_.message -match "TargetObject.*.*\\Control\\Terminal Server\\fDenyTSConnections")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_rdp_settings_hijack";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_rdp_settings_hijack";
            $detectedMessage = "Detects changes to RDP terminal service sensitive settings";
            $result = $event |  where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "TargetObject.*.*\\services\\TermService\\Parameters\\ServiceDll" -or $_.message -match "TargetObject.*.*\\Control\\Terminal Server\\fSingleSessionPerUser" -or $_.message -match "TargetObject.*.*\\Control\\Terminal Server\\fDenyTSConnections")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
