# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and $_.message -match "TargetObject.*.*System\\CurrentControlSet\\Services\\VSS.*" -and  -not ($_.message -match "TargetObject.*.*System\\CurrentControlSet\\Services\\VSS\\Start.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_volume_shadow_copy_service_keys";
    $detectedMessage = "Detects the volume shadow copy service initialization and processing. Registry keys such as HKLM\\System\\CurrentControlSet\\Services\\VSS\\Diag\\VolSnap\\Volume are captured.";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and $_.message -match "TargetObject.*.*System\\CurrentControlSet\\Services\\VSS.*" -and -not ($_.message -match "TargetObject.*.*System\\CurrentControlSet\\Services\\VSS\\Start.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\\$ruleName";
                result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
