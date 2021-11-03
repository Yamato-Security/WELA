# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*.*SYSTEM\\" -and $_.message -match "TargetObject.*.*ControlSet" -and $_.message -match "TargetObject.*.*\\Control\\Lsa" -and ($_.message -match "TargetObject.*.*\\lmcompatibilitylevel" -or $_.message -match "TargetObject.*.*\\NtlmMinClientSec" -or $_.message -match "TargetObject.*.*\\RestrictSendingNTLMTraffic")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Security | where {($_.ID -eq "4657" -and $_.message -match "ObjectName.*.*\\REGISTRY\\MACHINE\\SYSTEM" -and $_.message -match "ObjectName.*.*ControlSet" -and $_.message -match "ObjectName.*.*\\Control\\Lsa" -and ($_.message -match "LmCompatibilityLevel" -or $_.message -match "NtlmMinClientSec" -or $_.message -match "RestrictSendingNTLMTraffic")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_net_ntlm_downgrade";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "win_net_ntlm_downgrade";
            $detectedMessage = "Detects NetNTLM downgrade attack"
            $results = [System.Collections.ArrayList] @();
            $tmp = $event | where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*.*SYSTEM\\" -and $_.message -match "TargetObject.*.*ControlSet" -and $_.message -match "TargetObject.*.*\\Control\\Lsa" -and ($_.message -match "TargetObject.*.*\\lmcompatibilitylevel" -or $_.message -match "TargetObject.*.*\\NtlmMinClientSec" -or $_.message -match "TargetObject.*.*\\RestrictSendingNTLMTraffic")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { ($_.ID -eq "4657" -and $_.message -match "ObjectName.*.*\\REGISTRY\\MACHINE\\SYSTEM" -and $_.message -match "ObjectName.*.*ControlSet" -and $_.message -match "ObjectName.*.*\\Control\\Lsa" -and ($_.message -match "LmCompatibilityLevel" -or $_.message -match "NtlmMinClientSec" -or $_.message -match "RestrictSendingNTLMTraffic")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            
            foreach ($result in $results) {
                if ($result -and $result.Count -ne 0) {
                    Write-Output ""; 
                    Write-Output "Detected! RuleName:$ruleName";
                    Write-Output $detectedMessage;    
                    Write-Output $result;
                    Write-Output ""; 
                }
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
