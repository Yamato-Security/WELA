# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*cscript" -and $_.message -match "CommandLine.*.*manage-bde.wsf") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_manage-bde_lolbas";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_manage-bde_lolbas";
            $detectedMessage = "Detects a usage of the manage-bde.wsf script that may indicate an attempt of proxy execution from script";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*cscript" -and $_.message -match "CommandLine.*.*manage-bde.wsf") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
