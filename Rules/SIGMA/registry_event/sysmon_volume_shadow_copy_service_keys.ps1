# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and $_.message -match "TargetObject.*.*System\\CurrentControlSet\\Services\\VSS" -and  -not ($_.message -match "TargetObject.*.*System\\CurrentControlSet\\Services\\VSS\\Start")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_volume_shadow_copy_service_keys";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_volume_shadow_copy_service_keys";
            $detectedMessage = "Detects the volume shadow copy service initialization and processing. Registry keys such as HKLM\System\CurrentControlSet\Services\VSS\Diag\VolSnap\Volume are captured.";
            $result = $event |  where { ((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and $_.message -match "TargetObject.*.*System\\CurrentControlSet\\Services\\VSS" -and -not ($_.message -match "TargetObject.*.*System\\CurrentControlSet\\Services\\VSS\\Start")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result -and $result.Count -ne 0) {
                Write-Output ""; 
                Write-Output "Detected! RuleName:$ruleName";
                result;
                Write-Output $detectedMessage;
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
