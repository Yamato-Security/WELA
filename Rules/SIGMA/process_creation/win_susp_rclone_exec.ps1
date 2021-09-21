# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.* pass .*" -or $_.message -match "CommandLine.*.* user .*" -or $_.message -match "CommandLine.*.* copy .*" -or $_.message -match "CommandLine.*.* mega .*" -or $_.message -match "CommandLine.*.* sync .*" -or $_.message -match "CommandLine.*.* config .*" -or $_.message -match "CommandLine.*.* lsd .*" -or $_.message -match "CommandLine.*.* remote .*" -or $_.message -match "CommandLine.*.* ls .*") -and ($_.ID -eq "1") -and ($_.message -match "Description.*Rsync for cloud storage" -or ($_.message -match "Image.*.*\\rclone.exe" -and ($_.message -match "ParentImage.*.*\\PowerShell.exe" -or $_.message -match "ParentImage.*.*\\cmd.exe")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_rclone_exec";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_rclone_exec";
            $detectedMessage = "Detects Rclone which is commonly used by ransomware groups for exfiltration";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.* pass .*" -or $_.message -match "CommandLine.*.* user .*" -or $_.message -match "CommandLine.*.* copy .*" -or $_.message -match "CommandLine.*.* mega .*" -or $_.message -match "CommandLine.*.* sync .*" -or $_.message -match "CommandLine.*.* config .*" -or $_.message -match "CommandLine.*.* lsd .*" -or $_.message -match "CommandLine.*.* remote .*" -or $_.message -match "CommandLine.*.* ls .*") -and ($_.ID -eq "1") -and ($_.message -match "Description.*Rsync for cloud storage" -or ($_.message -match "Image.*.*\\rclone.exe" -and ($_.message -match "ParentImage.*.*\\PowerShell.exe" -or $_.message -match "ParentImage.*.*\\cmd.exe")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
