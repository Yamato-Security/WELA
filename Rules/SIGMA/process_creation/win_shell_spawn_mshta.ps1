# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\\mshta.exe" -and ($_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\cmd.exe" -or $_.message -match "Image.*.*\\WScript.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_shell_spawn_mshta";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_shell_spawn_mshta";
            $detectedMessage = "Detects a suspicious child process of a mshta.exe process";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\\mshta.exe" -and ($_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\cmd.exe" -or $_.message -match "Image.*.*\\WScript.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
