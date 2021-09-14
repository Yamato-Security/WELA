# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*verb:sync.*" -and $_.message -match "CommandLine.*.*-source:RunCommand.*" -and $_.message -match "CommandLine.*.*-dest:runCommand.*" -and ($_.message -match "Image.*.*\msdeploy.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "process_creation_msdeploy";
    $detectedMessage = "Detects file execution using the msdeploy.exe lolbin";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*verb:sync.*" -and $_.message -match "CommandLine.*.*-source:RunCommand.*" -and $_.message -match "CommandLine.*.*-dest:runCommand.*" -and ($_.message -match "Image.*.*\msdeploy.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
