# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\update.exe" -and ($_.message -match "CommandLine.*.*--processStart" -or $_.message -match "CommandLine.*.*--processStartAndWait" -or $_.message -match "CommandLine.*.*--createShortcut") -and $_.message -match "CommandLine.*.*.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_squirrel_lolbin";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_squirrel_lolbin";
            $detectedMessage = "Detects Possible Squirrel Packages Manager as Lolbin";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\update.exe" -and ($_.message -match "CommandLine.*.*--processStart" -or $_.message -match "CommandLine.*.*--processStartAndWait" -or $_.message -match "CommandLine.*.*--createShortcut") -and $_.message -match "CommandLine.*.*.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
