# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\sqlservr.exe" -and ($_.message -match "Image.*.*\cmd.exe" -or $_.message -match "Image.*.*\sh.exe" -or $_.message -match "Image.*.*\bash.exe" -or $_.message -match "Image.*.*\powershell.exe" -or $_.message -match "Image.*.*\bitsadmin.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_shell_spawn_from_mssql";
    $detectedMessage = "Detects suspicious shell spawn from MSSQL process, this might be sight of RCE or SQL Injection";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\sqlservr.exe" -and ($_.message -match "Image.*.*\cmd.exe" -or $_.message -match "Image.*.*\sh.exe" -or $_.message -match "Image.*.*\bash.exe" -or $_.message -match "Image.*.*\powershell.exe" -or $_.message -match "Image.*.*\bitsadmin.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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