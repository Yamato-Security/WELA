# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\plink.exe" -or $_.message -match "Image.*.*\socat.exe" -or $_.message -match "Image.*.*\stunnel.exe" -or $_.message -match "Image.*.*\httptunnel.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_exfiltration_and_tunneling_tools_execution";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_exfiltration_and_tunneling_tools_execution";
            $detectedMessage = "Execution of well known tools for data exfiltration and tunneling";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "Image.*.*\\plink.exe" -or $_.message -match "Image.*.*\\socat.exe" -or $_.message -match "Image.*.*\\stunnel.exe" -or $_.message -match "Image.*.*\\httptunnel.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error" -Foreground Yellow;
    }
}
