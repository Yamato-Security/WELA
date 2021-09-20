# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "TargetObject.*.*\\services\\TermService\\Parameters\\ServiceDll.*" -or $_.message -match "TargetObject.*.*\\Control\\Terminal Server\\fSingleSessionPerUser.*" -or $_.message -match "TargetObject.*.*\\Control\\Terminal Server\\fDenyTSConnections.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_rdp_settings_hijack";
    $detectedMessage = "Detects changes to RDP terminal service sensitive settings";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "TargetObject.*.*\\services\\TermService\\Parameters\\ServiceDll.*" -or $_.message -match "TargetObject.*.*\\Control\\Terminal Server\\fSingleSessionPerUser.*" -or $_.message -match "TargetObject.*.*\\Control\\Terminal Server\\fDenyTSConnections.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
