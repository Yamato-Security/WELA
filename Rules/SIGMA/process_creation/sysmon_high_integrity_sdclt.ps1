# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*sdclt.exe" -and $_.message -match "IntegrityLevel.*High") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_high_integrity_sdclt";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_high_integrity_sdclt";
            $detectedMessage = "A General detection for sdclt being spawned as an elevated process. This could be an indicator of sdclt being used for bypass UAC techniques.";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*sdclt.exe" -and $_.message -match "IntegrityLevel.*High") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error" -Foreground Yellow;
    }
}
