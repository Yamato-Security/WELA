# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and $_.message -match "TargetObject.*.*\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" -and (($_.message -match "Details.*C:\\Windows\\Temp\\" -or $_.message -match "Details.*C:\\ProgramData\\" -or $_.message -match "Details.*C:\\$Recycle.bin\\" -or $_.message -match "Details.*C:\\Temp\\" -or $_.message -match "Details.*C:\\Users\\Public\\" -or $_.message -match "Details.*C:\\Users\\Default\\") -or ($_.message -match "Details.*.*\\AppData\\"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_reg_persist_explorer_run";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_susp_reg_persist_explorer_run";
            $detectedMessage = "Detects a possible persistence mechanism using RUN key for Windows Explorer and pointing to a suspicious folder";
            $result = $event |  where { ((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and $_.message -match "TargetObject.*.*\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" -and (($_.message -match "Details.*C:\\Windows\\Temp\\" -or $_.message -match "Details.*C:\\ProgramData\\" -or $_.message -match "Details.*C:\\\$Recycle.bin\\" -or $_.message -match "Details.*C:\\Temp\\" -or $_.message -match "Details.*C:\\Users\\Public\\" -or $_.message -match "Details.*C:\\Users\\Default\\") -or ($_.message -match "Details.*.*\\AppData\\"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
