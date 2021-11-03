# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*regsvr32" -and $_.message -match "CommandLine.*.*/s" -and $_.message -match "CommandLine.*.*/i" -and $_.message -match "CommandLine.*.*\AppData\Roaming\" -and $_.message -match "CommandLine.*.*.ocx") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_evilnum_jul20";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_apt_evilnum_jul20";
            $detectedMessage = "Detects Golden Chickens deployment method as used by Evilnum in report published in July 2020";
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*regsvr32" -and $_.message -match "CommandLine.*.*/s" -and $_.message -match "CommandLine.*.*/i" -and $_.message -match "CommandLine.*.*\\AppData\\Roaming\\" -and $_.message -match "CommandLine.*.*.ocx") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
