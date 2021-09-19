# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\expand.exe") -and ($_.message -match "CommandLine.*.*.cab.*" -or $_.message -match "CommandLine.*.*/F:.*" -or $_.message -match "CommandLine.*.*C:\ProgramData\.*" -or $_.message -match "CommandLine.*.*C:\Public\.*" -or $_.message -match "CommandLine.*.*\AppData\Local\Temp\.*" -or $_.message -match "CommandLine.*.*\AppData\Roaming\Temp\.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_expand_cabinet_files";
    $detectedMessage = "Adversaries can use the inbuilt expand utility to decompress cab files as seen in recent Iranian MeteorExpress attack";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "1" -and ($_.message -match "Image.*.*\expand.exe") -and ($_.message -match "CommandLine.*.*.cab.*" -or $_.message -match "CommandLine.*.*/F:.*" -or $_.message -match "CommandLine.*.*C:\ProgramData\.*" -or $_.message -match "CommandLine.*.*C:\Public\.*" -or $_.message -match "CommandLine.*.*\AppData\Local\Temp\.*" -or $_.message -match "CommandLine.*.*\AppData\Roaming\Temp\.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
