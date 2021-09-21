# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "8" -and $_.message -match "SourceImage.*.*\powershell.exe" -and $_.message -match "TargetImage.*.*\rundll32.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_powershell_rundll32";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_susp_powershell_rundll32";
            $detectedMessage = "Detects PowerShell remote thread creation in Rundll32.exe";
            $result = $event |  where { ($_.ID -eq "8" -and $_.message -match "SourceImage.*.*\\powershell.exe" -and $_.message -match "TargetImage.*.*\\rundll32.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    $ruleStack.Add($ruleName, $detectRule);
}
