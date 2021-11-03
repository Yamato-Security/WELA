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
            $result = $event |  where { (($_.ID -eq "1") -and ((($_.message -match "ParentImage.*.*\\wmiprvse.exe") -and ($_.message -match "Image.*.*\\powershell.exe")) -and -not ($_.message -match "CommandLine.*null")) -and -not (-not $_.message -match "CommandLine")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
