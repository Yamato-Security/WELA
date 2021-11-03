# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ((($_.ID -eq "1") -and $_.message -match "CommandLine.*.*.cpl" -and  -not (($_.message -match "CommandLine.*.*\System32\" -or $_.message -match "CommandLine.*.*%System%"))) -or ($_.ID -eq "1" -and $_.message -match "Image.*.*\reg.exe" -and $_.message -match "CommandLine.*.*add" -and ($_.message -match "CommandLine.*.*CurrentVersion\Control Panel\CPLs")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_control_panel_item";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_control_panel_item";
            $detectedMessage = "Detects the malicious use of a control panel item";
            $result = $event |  where { (($_.ID -eq "1") -and ((($_.ID -eq "1") -and $_.message -match "CommandLine.*.*.cpl" -and -not (($_.message -match "CommandLine.*.*\\System32\\" -or $_.message -match "CommandLine.*.*%System%"))) -or ($_.ID -eq "1" -and $_.message -match "Image.*.*\\reg.exe" -and $_.message -match "CommandLine.*.*add" -and ($_.message -match "CommandLine.*.*CurrentVersion\\Control Panel\\CPLs")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
