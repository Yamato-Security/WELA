# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "Description.*Rsync for cloud storage" -or ($_.message -match "CommandLine.*.*--config .*" -and $_.message -match "CommandLine.*.*--no-check-certificate .*" -and $_.message -match "CommandLine.*.* copy .*") -or (($_.message -match "Image.*.*\rclone.exe") -and ($_.message -match "CommandLine.*.*mega.*" -or $_.message -match "CommandLine.*.*pcloud.*" -or $_.message -match "CommandLine.*.*ftp.*" -or $_.message -match "CommandLine.*.*--progress.*" -or $_.message -match "CommandLine.*.*--ignore-existing.*" -or $_.message -match "CommandLine.*.*--auto-confirm.*" -or $_.message -match "CommandLine.*.*--transfers.*" -or $_.message -match "CommandLine.*.*--multi-thread-streams.*")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_rclone_execution";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_rclone_execution";
            $detectedMessage = "Detects execution of RClone utility for exfiltration as used by various ransomwares strains like REvil, Conti, FiveHands, etc";
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "Description.*Rsync for cloud storage" -or ($_.message -match "CommandLine.*.*--config .*" -and $_.message -match "CommandLine.*.*--no-check-certificate .*" -and $_.message -match "CommandLine.*.* copy .*") -or (($_.message -match "Image.*.*\\rclone.exe") -and ($_.message -match "CommandLine.*.*mega.*" -or $_.message -match "CommandLine.*.*pcloud.*" -or $_.message -match "CommandLine.*.*ftp.*" -or $_.message -match "CommandLine.*.*--progress.*" -or $_.message -match "CommandLine.*.*--ignore-existing.*" -or $_.message -match "CommandLine.*.*--auto-confirm.*" -or $_.message -match "CommandLine.*.*--transfers.*" -or $_.message -match "CommandLine.*.*--multi-thread-streams.*")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
