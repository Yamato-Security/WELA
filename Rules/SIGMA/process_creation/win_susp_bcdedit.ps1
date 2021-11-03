# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\bcdedit.exe" -and ($_.message -match "CommandLine.*.*delete" -or $_.message -match "CommandLine.*.*deletevalue" -or $_.message -match "CommandLine.*.*import" -or $_.message -match "CommandLine.*.*safeboot" -or $_.message -match "CommandLine.*.*network")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_bcdedit";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_bcdedit";
            $detectedMessage = "Detects, possibly, malicious unauthorized usage of bcdedit.exe";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\bcdedit.exe" -and ($_.message -match "CommandLine.*.*delete" -or $_.message -match "CommandLine.*.*deletevalue" -or $_.message -match "CommandLine.*.*import" -or $_.message -match "CommandLine.*.*safeboot" -or $_.message -match "CommandLine.*.*network")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
