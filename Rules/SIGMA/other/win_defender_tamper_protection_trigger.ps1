# Get-WinEvent -LogName Microsoft-Windows-Windows Defender/Operational | where {(($_.ID -eq "5013") -and ($_.message -match "Value.*.*\Windows Defender\DisableAntiSpyware = 0x1()" -or $_.message -match "Value.*.*\Real-Time Protection\DisableRealtimeMonitoring = (Current)")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_defender_tamper_protection_trigger";
    $detectedMessage = "Detects block of attempt to disable real time protection of Microsoft Defender by tamper protection";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "5013") -and ($_.message -match "Value.*.*\\Windows Defender\\DisableAntiSpyware = 0x1()" -or $_.message -match "Value.*.*\\Real-Time Protection\\DisableRealtimeMonitoring = (Current)")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
