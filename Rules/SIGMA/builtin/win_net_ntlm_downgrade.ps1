# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*.*SYSTEM\\.*" -and $_.message -match "TargetObject.*.*ControlSet.*" -and $_.message -match "TargetObject.*.*\\Control\\Lsa.*" -and ($_.message -match "TargetObject.*.*\\lmcompatibilitylevel" -or $_.message -match "TargetObject.*.*\\NtlmMinClientSec" -or $_.message -match "TargetObject.*.*\\RestrictSendingNTLMTraffic")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Security | where {($_.ID -eq "4657" -and $_.message -match "ObjectName.*.*\\REGISTRY\\MACHINE\\SYSTEM.*" -and $_.message -match "ObjectName.*.*ControlSet.*" -and $_.message -match "ObjectName.*.*\\Control\\Lsa.*" -and ($_.message -match "LmCompatibilityLevel" -or $_.message -match "NtlmMinClientSec" -or $_.message -match "RestrictSendingNTLMTraffic")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_net_ntlm_downgrade";
    $detectedMessage = "Detects NetNTLM downgrade attack";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*.*SYSTEM\\.*" -and $_.message -match "TargetObject.*.*ControlSet.*" -and $_.message -match "TargetObject.*.*\\Control\\Lsa.*" -and ($_.message -match "TargetObject.*.*\\lmcompatibilitylevel" -or $_.message -match "TargetObject.*.*\\NtlmMinClientSec" -or $_.message -match "TargetObject.*.*\\RestrictSendingNTLMTraffic")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $result2 = $event | where { ($_.ID -eq "4657" -and $_.message -match "ObjectName.*.*\\REGISTRY\\MACHINE\\SYSTEM.*" -and $_.message -match "ObjectName.*.*ControlSet.*" -and $_.message -match "ObjectName.*.*\\Control\\Lsa.*" -and ($_.message -match "LmCompatibilityLevel" -or $_.message -match "NtlmMinClientSec" -or $_.message -match "RestrictSendingNTLMTraffic")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            
            if (($result.Count -ne 0) -or ($result2.Count -ne 0)) {
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
