# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*System.Management.Automation.AmsiUtils") -and ($_.message -match "CommandLine.*.*amsiInitFailed")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_powershell_amsi_bypass";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_powershell_amsi_bypass";
            $detectedMessage = "Detects Request to amsiInitFailed that can be used to disable AMSI Scanning";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*System.Management.Automation.AmsiUtils") -and ($_.message -match "CommandLine.*.*amsiInitFailed")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
