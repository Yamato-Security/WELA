# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*Temp\wtask.exe /create" -or $_.message -match "CommandLine.*.*%windir:~-3,1%%PUBLIC:~-9,1%" -or $_.message -match "CommandLine.*.*/tn "Security Script " -or $_.message -match "CommandLine.*.*%windir:~-1,1%") -or ($_.message -match "CommandLine.*.*/E:vbscript" -and $_.message -match "CommandLine.*.*C:\Users\" -and $_.message -match "CommandLine.*.*.txt" -and $_.message -match "CommandLine.*.*/F") -or $_.message -match "Image.*.*Temp\winwsh.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_mustangpanda";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_apt_mustangpanda";
            $detectedMessage = "Detects specific process parameters as used by Mustang Panda droppers";
            $result = $event | where { (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*Temp\\wtask.exe /create" -or $_.message -match "CommandLine.*.*%windir:~-3,1%%PUBLIC:~-9,1%" -or $_.message -match "CommandLine.*.*/tn Security Script " -or $_.message -match "CommandLine.*.*%windir:~-1, 1%") -or ($_.message -match "CommandLine.*.*/E:vbscript" -and $_.message -match "CommandLine.*.*C:\\Users\\" -and $_.message -match "CommandLine.*.*.txt" -and $_.message -match "CommandLine.*.*/F") -or $_.message -match "Image.*.*Temp\\winwsh.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
