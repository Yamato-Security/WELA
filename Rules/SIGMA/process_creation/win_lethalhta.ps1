# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\svchost.exe" -and $_.message -match "Image.*.*\mshta.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_lethalhta";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_lethalhta";
            $detectedMessage = "Detects MSHTA.EXE spwaned by SVCHOST as seen in LethalHTA and described in report";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\\svchost.exe" -and $_.message -match "Image.*.*\\mshta.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
