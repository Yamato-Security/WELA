# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.ID -eq "1") -and ((($_.message -match "Image.*.*\\robocopy.exe" -or $_.message -match "Image.*.*\\xcopy.exe") -or ($_.message -match "Image.*.*\\cmd.exe" -and $_.message -match "CommandLine.*.*copy")) -or ($_.message -match "Image.*.*\\powershell" -and ($_.message -match "CommandLine.*.*copy-item" -or $_.message -match "CommandLine.*.*copy" -or $_.message -match "CommandLine.*.*cpi " -or $_.message -match "CommandLine.*.* cp "))) -and ($_.message -match "CommandLine.*.*\\\\" -and $_.message -match "CommandLine.*.*$")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_copy_lateral_movement";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_copy_lateral_movement";
            $detectedMessage = "Detects a suspicious copy command to or from an Admin share";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.ID -eq "1") -and ((($_.message -match "Image.*.*\\robocopy.exe" -or $_.message -match "Image.*.*\\xcopy.exe") -or ($_.message -match "Image.*.*\\cmd.exe" -and $_.message -match "CommandLine.*.*copy")) -or ($_.message -match "Image.*.*\\powershell" -and ($_.message -match "CommandLine.*.*copy-item" -or $_.message -match "CommandLine.*.*copy" -or $_.message -match "CommandLine.*.*cpi " -or $_.message -match "CommandLine.*.* cp "))) -and ($_.message -match "CommandLine.*.*\\\\" -and $_.message -match "CommandLine.*.*$")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
