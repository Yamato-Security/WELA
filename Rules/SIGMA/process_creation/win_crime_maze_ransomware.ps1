# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ((($_.message -match "ParentImage.*.*\WINWORD.exe") -and ($_.message -match "Image.*.*.tmp")) -or ($_.message -match "Image.*.*\wmic.exe" -and $_.message -match "ParentImage.*.*\Temp\" -and $_.message -match "CommandLine.*.*shadowcopy delete") -or ($_.message -match "CommandLine.*.*shadowcopy delete" -and $_.message -match "CommandLine.*.*\..\..\system32"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_crime_maze_ransomware";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "win_crime_maze_ransomware";
                    $detectedMessage = "Detects specific process characteristics of Maze ransomware word document droppers";
                $result = $event |  where { (($_.ID -eq "1") -and ((($_.message -match "ParentImage.*.*\\WINWORD.exe") -and ($_.message -match "Image.*.*.tmp")) -or ($_.message -match "Image.*.*\\wmic.exe" -and $_.message -match "ParentImage.*.*\\Temp\\" -and $_.message -match "CommandLine.*.*shadowcopy delete") -or ($_.message -match "CommandLine.*.*shadowcopy delete" -and $_.message -match "CommandLine.*.*\\..\\..\\system32"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
