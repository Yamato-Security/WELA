# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and (($_.message -match "CommandLine.*.*cmd.exe /c " -and $_.message -match "CommandLine.*.* -p 0x" -and ($_.message -match "CommandLine.*.*C:\ProgramData\" -or $_.message -match "CommandLine.*.*C:\RECYCLER\")) -or ($_.message -match "CommandLine.*.*rundll32.exe " -and $_.message -match "CommandLine.*.*C:\ProgramData\" -and ($_.message -match "CommandLine.*.*.bin," -or $_.message -match "CommandLine.*.*.tmp," -or $_.message -match "CommandLine.*.*.dat," -or $_.message -match "CommandLine.*.*.io," -or $_.message -match "CommandLine.*.*.ini," -or $_.message -match "CommandLine.*.*.db,")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_lazarus_loader";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_apt_lazarus_loader";
            $detectedMessage = "Detects different loaders as described in various threat reports on Lazarus group activity";
            $result = $event | where { ($_.ID -eq "1" -and (($_.message -match "CommandLine.*.*cmd.exe /c " -and $_.message -match "CommandLine.*.* -p 0x" -and ($_.message -match "CommandLine.*.*C:\\ProgramData\\" -or $_.message -match "CommandLine.*.*C:\\RECYCLER\\")) -or ($_.message -match "CommandLine.*.*rundll32.exe " -and $_.message -match "CommandLine.*.*C:\\ProgramData\\" -and ($_.message -match "CommandLine.*.*.bin," -or $_.message -match "CommandLine.*.*.tmp," -or $_.message -match "CommandLine.*.*.dat," -or $_.message -match "CommandLine.*.*.io," -or $_.message -match "CommandLine.*.*.ini," -or $_.message -match "CommandLine.*.*.db,")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
