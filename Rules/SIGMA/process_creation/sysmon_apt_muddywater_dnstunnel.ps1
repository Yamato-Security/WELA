# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\powershell.exe") -and ($_.message -match "ParentImage.*.*\excel.exe") -and ($_.message -match "CommandLine.*.*DataExchange.dll")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_apt_muddywater_dnstunnel";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_apt_muddywater_dnstunnel";
            $detectedMessage = "Detecting DNS tunnel activity for Muddywater actor";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "Image.*.*\\powershell.exe") -and ($_.message -match "ParentImage.*.*\\excel.exe") -and ($_.message -match "CommandLine.*.*DataExchange.dll")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
