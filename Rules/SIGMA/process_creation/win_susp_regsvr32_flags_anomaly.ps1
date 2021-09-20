# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "Image.*.*\\regsvr32.exe" -and $_.message -match "CommandLine.*.* /i:.*") -and  -not ($_.message -match "CommandLine.*.* /n .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_regsvr32_flags_anomaly";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "win_susp_regsvr32_flags_anomaly";
                $result = $event | where { (($_.ID -eq "1") -and ($_.message -match "Image.*.*\\regsvr32.exe" -and $_.message -match "CommandLine.*.* /i:.*") -and -not ($_.message -match "CommandLine.*.* /n .*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
