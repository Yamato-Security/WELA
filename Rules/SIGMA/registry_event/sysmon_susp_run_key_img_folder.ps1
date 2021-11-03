# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\") -and (($_.message -match "Details.*.*C:\\Windows\\Temp\\" -or $_.message -match "Details.*.*C:\\$Recycle.bin\\" -or $_.message -match "Details.*.*C:\\Temp\\" -or $_.message -match "Details.*.*C:\\Users\\Public\\" -or $_.message -match "Details.*.*C:\\Users\\Default\\" -or $_.message -match "Details.*.*C:\\Users\\Desktop\\") -or ($_.message -match "Details.*%Public%\\" -or $_.message -match "Details.*wscript" -or $_.message -match "Details.*cscript"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_run_key_img_folder";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_susp_run_key_img_folder";
            $detectedMessage = "Detects suspicious new RUN key element pointing to an executable in a suspicious folder";
            $result = $event |  where { ((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\") -and (($_.message -match "Details.*.*C:\\Windows\\Temp\\" -or $_.message -match "Details.*.*C:\\\$Recycle.bin\\" -or $_.message -match "Details.*.*C:\\Temp\\" -or $_.message -match "Details.*.*C:\\Users\\Public\\" -or $_.message -match "Details.*.*C:\\Users\\Default\\" -or $_.message -match "Details.*.*C:\\Users\\Desktop\\") -or ($_.message -match "Details.*%Public%\\" -or $_.message -match "Details.*wscript" -or $_.message -match "Details.*cscript"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
