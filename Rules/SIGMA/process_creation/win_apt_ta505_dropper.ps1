# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\mshta.exe" -and $_.message -match "ParentImage.*.*\wmiprvse.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_ta505_dropper";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_apt_ta505_dropper";
            $detectedMessage = "Detects mshta loaded by wmiprvse as parent as used by TA505 malicious documents";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\mshta.exe" -and $_.message -match "ParentImage.*.*\\wmiprvse.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
