# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\powershell.exe") -and ($_.message -match "ParentImage.*.*\excel.exe") -and ($_.message -match "CommandLine.*.*DataExchange.dll.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_apt_muddywater_dnstunnel";
    $detectedMessage = "Detecting DNS tunnel activity for Muddywater actor";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "Image.*.*\\powershell.exe") -and ($_.message -match "ParentImage.*.*\\excel.exe") -and ($_.message -match "CommandLine.*.*DataExchange.dll.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
