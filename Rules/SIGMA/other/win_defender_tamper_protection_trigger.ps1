# Get-WinEvent -LogName Microsoft-Windows-Windows Defender/Operational | where {(($_.ID -eq "5013") -and ($_.message -match "Value.*.*\Windows Defender\DisableAntiSpyware = 0x1()" -or $_.message -match "Value.*.*\Real-Time Protection\DisableRealtimeMonitoring = (Current)")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_defender_tamper_protection_trigger";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_defender_tamper_protection_trigger";
            $detectedMessage = "Detects block of attempt to disable real time protection of Microsoft Defender by tamper protection";
            $result = $event |  where { (($_.ID -eq "5013") -and ($_.message -match "Value.*.*\\Windows Defender\\DisableAntiSpyware = 0x1()" -or $_.message -match "Value.*.*\\Real-Time Protection\\DisableRealtimeMonitoring = (Current)")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
