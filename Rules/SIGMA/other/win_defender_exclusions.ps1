Get-WinEvent -LogName Microsoft-Windows-Windows Defender/Operational | where { (($_.ID -eq "5007") -and ($_.message -match "New Value.*.*\\Microsoft\\Windows Defender\\Exclusions.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.ID -eq "13") -and ($_.message -match "TargetObject.*.*\\Microsoft\\Windows Defender\\Exclusions.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_defender_exclusions";
    $detectedMessage = "Detects the Setting of Windows Defender Exclusions"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { (($_.ID -eq "5007") -and ($_.message -match "New Value.*.*\\Microsoft\\Windows Defender\\Exclusions.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            $result2 = $event | where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.ID -eq "13") -and ($_.message -match "TargetObject.*.*\\Microsoft\\Windows Defender\\Exclusions.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            
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
