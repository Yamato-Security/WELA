# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\expand.exe") -and ($_.message -match "CommandLine.*.*.cab" -or $_.message -match "CommandLine.*.*/F:" -or $_.message -match "CommandLine.*.*C:\ProgramData\" -or $_.message -match "CommandLine.*.*C:\Public\" -or $_.message -match "CommandLine.*.*\AppData\Local\Temp\" -or $_.message -match "CommandLine.*.*\AppData\Roaming\Temp\")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_expand_cabinet_files";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_expand_cabinet_files";
            $detectedMessage = "Adversaries can use the inbuilt expand utility to decompress cab files as seen in recent Iranian MeteorExpress attack";
            $result = $event | where { ($_.ID -eq "1" -and ($_.message -match "Image.*.*\\expand.exe") -and ($_.message -match "CommandLine.*.*.cab" -or $_.message -match "CommandLine.*.*/F:" -or $_.message -match "CommandLine.*.*C:\\ProgramData\\" -or $_.message -match "CommandLine.*.*C:\\Public\\" -or $_.message -match "CommandLine.*.*\\AppData\\Local\\Temp\\" -or $_.message -match "CommandLine.*.*\\AppData\\Roaming\\Temp\\")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
