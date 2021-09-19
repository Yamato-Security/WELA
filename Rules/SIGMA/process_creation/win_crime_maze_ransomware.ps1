# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ((($_.message -match "ParentImage.*.*\WINWORD.exe") -and ($_.message -match "Image.*.*.tmp")) -or ($_.message -match "Image.*.*\wmic.exe" -and $_.message -match "ParentImage.*.*\Temp\.*" -and $_.message -match "CommandLine.*.*shadowcopy delete") -or ($_.message -match "CommandLine.*.*shadowcopy delete" -and $_.message -match "CommandLine.*.*\..\..\system32.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_crime_maze_ransomware";
    $detectedMessage = "Detects specific process characteristics of Maze ransomware word document droppers";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and ((($_.message -match "ParentImage.*.*\WINWORD.exe") -and ($_.message -match "Image.*.*.tmp")) -or ($_.message -match "Image.*.*\wmic.exe" -and $_.message -match "ParentImage.*.*\Temp\.*" -and $_.message -match "CommandLine.*.*shadowcopy delete") -or ($_.message -match "CommandLine.*.*shadowcopy delete" -and $_.message -match "CommandLine.*.*\..\..\system32.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
