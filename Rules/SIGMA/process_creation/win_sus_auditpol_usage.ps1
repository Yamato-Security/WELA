# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\auditpol.exe" -and ($_.message -match "CommandLine.*.*disable" -or $_.message -match "CommandLine.*.*clear" -or $_.message -match "CommandLine.*.*remove" -or $_.message -match "CommandLine.*.*restore")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_sus_auditpol_usage";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_sus_auditpol_usage";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\auditpol.exe" -and ($_.message -match "CommandLine.*.*disable" -or $_.message -match "CommandLine.*.*clear" -or $_.message -match "CommandLine.*.*remove" -or $_.message -match "CommandLine.*.*restore")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
