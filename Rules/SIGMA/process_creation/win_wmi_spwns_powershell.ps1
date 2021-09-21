# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ((($_.message -match "ParentImage.*.*\\wmiprvse.exe") -and ($_.message -match "Image.*.*\\powershell.exe")) -and  -not ($_.message -match "CommandLine.*null")) -and  -not (-not CommandLine="*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_wmi_spwns_powershell";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_wmi_spwns_powershell";
            $detectedMessage = "Detects WMI spawning PowerShell";
            $result = $event |  where { (($_.ID -eq "1") -and ((($_.message -match "ParentImage.*.*\\wmiprvse.exe") -and ($_.message -match "Image.*.*\\powershell.exe")) -and -not ($_.message -match "CommandLine.*null")) -and -not (-not $_.message -match "CommandLine.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
