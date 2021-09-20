# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\.*" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\.*") -and (($_.message -match "Details.*.*C:\\Windows\\Temp\\.*" -or $_.message -match "Details.*.*C:\\$Recycle.bin\\.*" -or $_.message -match "Details.*.*C:\\Temp\\.*" -or $_.message -match "Details.*.*C:\\Users\\Public\\.*" -or $_.message -match "Details.*.*C:\\Users\\Default\\.*" -or $_.message -match "Details.*.*C:\\Users\\Desktop\\.*") -or ($_.message -match "Details.*%Public%\\.*" -or $_.message -match "Details.*wscript.*" -or $_.message -match "Details.*cscript.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_run_key_img_folder";
    $detectedMessage = "Detects suspicious new RUN key element pointing to an executable in a suspicious folder";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\.*" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\.*") -and (($_.message -match "Details.*.*C:\\Windows\\Temp\\.*" -or $_.message -match "Details.*.*C:\\\$Recycle.bin\\.*" -or $_.message -match "Details.*.*C:\\Temp\\.*" -or $_.message -match "Details.*.*C:\\Users\\Public\\.*" -or $_.message -match "Details.*.*C:\\Users\\Default\\.*" -or $_.message -match "Details.*.*C:\\Users\\Desktop\\.*") -or ($_.message -match "Details.*%Public%\\.*" -or $_.message -match "Details.*wscript.*" -or $_.message -match "Details.*cscript.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
