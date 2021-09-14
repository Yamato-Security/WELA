# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\update.exe" -and ($_.message -match "CommandLine.*.*--processStart.*" -or $_.message -match "CommandLine.*.*--processStartAndWait.*" -or $_.message -match "CommandLine.*.*--createShortcut.*") -and $_.message -match "CommandLine.*.*.exe.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_squirrel_lolbin";
    $detectedMessage = "Detects Possible Squirrel Packages Manager as Lolbin";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "Image.*.*\update.exe" -and ($_.message -match "CommandLine.*.*--processStart.*" -or $_.message -match "CommandLine.*.*--processStartAndWait.*" -or $_.message -match "CommandLine.*.*--createShortcut.*") -and $_.message -match "CommandLine.*.*.exe.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
